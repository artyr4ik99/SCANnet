"""
topology.py - построение топологии сети и подготовка её к визуализации.

Два способа построения:

  * build_local_topology() - "логическая" топология без доступа к
    коммутаторам: этот компьютер -> шлюз -> узлы сегмента. Строится из уже
    отсканированных данных, сетевых вызовов не делает.

  * build_snmp_topology() - топология через управляемые коммутаторы:
    обходит LLDP-соседей (BRIDGE/LLDP-MIB, стандартные OID) и таблицы
    MAC-адресов за портами по SNMP (GETNEXT/walk), начиная с одного или
    нескольких указанных коммутаторов. Требует, чтобы на коммутаторе был
    включён SNMP (обычно read-only community, часто "public" по
    умолчанию) — работает только с управляемыми коммутаторами, которыми вы
    владеете или на аудит которых у вас есть разрешение.

Результат обоих способов - единый формат:
    {"nodes": {key: {"label": str, "type": str, ...}}, "edges": [(a, b[, label]), ...]}
который рисует GUI (netsuite.py, класс TopologyWindow) или который можно
экспортировать в Graphviz DOT функцией export_dot() для просмотра вне
приложения (`dot -Tpng topo.dot -o topo.png`, или вставить текст на
https://dreampuf.github.io/GraphvizOnline/).
"""
import ctypes
import os
import platform
import re
import socket
import subprocess
import sys

from netid import mac_vendor, snmp_get

IS_WIN = platform.system() == "Windows"

try:
    # scapy - необязательная зависимость, нужна только для пассивного
    # прослушивания LLDP/CDP (build_passive_topology). Остальной модуль
    # (локальная топология, SNMP-топология, раскладка, экспорт в DOT)
    # работает без неё.
    from scapy.all import sniff, Ether  # noqa: F401
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

NODE_COLORS = {
    "me": "#ff5555", "router": "#f0a500", "camera": "#19c3ff", "nas": "#b388ff",
    "printer": "#4caf50", "pc": "#4a90e2", "iot": "#ffd54f", "host": "#9aa5b1",
    "unknown": "#9aa5b1",
}


def _type_key(device_type):
    t = (device_type or "").lower()
    if "камер" in t:
        return "camera"
    if "роутер" in t or "коммутатор" in t or "шлюз" in t:
        return "router"
    if "nas" in t or "файлов" in t:
        return "nas"
    if "принтер" in t:
        return "printer"
    if "windows" in t or "linux" in t or " пк" in t or t.startswith("пк") or "сервер" in t:
        return "pc"
    if "iot" in t or "умное" in t:
        return "iot"
    return "unknown"


# ======================================================================
#  Локальная топология (без SNMP) - из уже отсканированных данных
# ======================================================================

def build_local_topology(hosts, my_ip=None, gateway_ip=None):
    """hosts - список словарей с ключами ip/mac/vendor/device_type (как
    строки scan_subnet/ScanWindow.rows). Узлы с известным MAC (видны по ARP,
    то есть в том же L2-сегменте) вешаются на этот компьютер, узлы без MAC
    (за маршрутизатором/в другом VLAN) - на шлюз, если он известен."""
    nodes, edges = {}, []
    me = my_ip or "me"
    nodes[me] = {"label": "Этот компьютер" + (f"\n{my_ip}" if my_ip else ""), "type": "me"}
    if gateway_ip and gateway_ip != my_ip:
        nodes[gateway_ip] = {"label": f"Шлюз\n{gateway_ip}", "type": "router"}
        edges.append((me, gateway_ip))
    for h in hosts:
        ip = h.get("ip")
        if not ip or ip in (my_ip, gateway_ip):
            continue
        dtype = h.get("device_type", "")
        vendor = h.get("vendor", "")
        label = "\n".join(x for x in (vendor or dtype or "Узел", ip) if x)
        nodes[ip] = {"label": label, "type": _type_key(dtype)}
        same_segment = bool(h.get("mac"))
        parent = me if (same_segment or not gateway_ip) else gateway_ip
        edges.append((parent, ip))
    return {"nodes": nodes, "edges": edges, "errors": []}


# ======================================================================
#  SNMP: минимальный GETNEXT (walk) поверх тех же BER-примитивов, что и
#  netid.snmp_get, но для обхода целой таблицы, а не одного значения.
# ======================================================================

def _ber_len(n):
    if n < 128:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def _ber_tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def _encode_oid(oid):
    parts = [int(x) for x in oid.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 128:
            body.append(p)
        else:
            chunk = [p & 0x7F]
            p >>= 7
            while p:
                chunk.insert(0, (p & 0x7F) | 0x80)
                p >>= 7
            body.extend(chunk)
    return bytes(body)


def _decode_oid(data):
    if not data:
        return ""
    first = data[0]
    parts = [first // 40, first % 40]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(val)
            val = 0
    return ".".join(map(str, parts))


def _read_tlv(data, pos):
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    value = data[pos:pos + length]
    return tag, value, pos + length


def snmp_walk(ip, base_oid, community="public", timeout=1.0, port=161, max_rows=256):
    """SNMPv1 GETNEXT в цикле: возвращает список (oid_строка, tag, value_bytes)
    для всех узлов поддерева base_oid. Останавливается, как только обход
    выходит за пределы base_oid, зацикливается, либо при любой ошибке
    (таймаут, устройство не поддерживает SNMP/эту ветку MIB и т.п.) —
    в этом случае просто возвращает то, что успело собраться (может быть
    пустым списком)."""
    results = []
    oid = base_oid
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        for _ in range(max_rows):
            req_id = int.from_bytes(os.urandom(2), "big")
            version = _ber_tlv(0x02, b"\x00")
            comm = _ber_tlv(0x04, community.encode())
            oid_enc = _ber_tlv(0x06, _encode_oid(oid))
            null_enc = _ber_tlv(0x05, b"")
            varbind = _ber_tlv(0x30, oid_enc + null_enc)
            varbindlist = _ber_tlv(0x30, varbind)
            rid = _ber_tlv(0x02, req_id.to_bytes(2, "big"))
            err = _ber_tlv(0x02, b"\x00")
            erridx = _ber_tlv(0x02, b"\x00")
            pdu = _ber_tlv(0xA1, rid + err + erridx + varbindlist)  # GetNextRequest-PDU
            packet = _ber_tlv(0x30, version + comm + pdu)
            s.sendto(packet, (ip, port))
            data, _ = s.recvfrom(4096)

            _, seq, _ = _read_tlv(data, 0)
            pos = 0
            _, _, pos = _read_tlv(seq, pos)       # version
            _, _, pos = _read_tlv(seq, pos)       # community
            _, pdu_val, _ = _read_tlv(seq, pos)    # GetResponse-PDU
            p2 = 0
            _, _, p2 = _read_tlv(pdu_val, p2)      # request-id
            _, _, p2 = _read_tlv(pdu_val, p2)      # error-status
            _, _, p2 = _read_tlv(pdu_val, p2)      # error-index
            _, vbl, _ = _read_tlv(pdu_val, p2)     # varbind list
            _, vb, _ = _read_tlv(vbl, 0)           # первый (и единственный) varbind
            p3 = 0
            _, oid_val, p3 = _read_tlv(vb, 0)
            tag, val, _ = _read_tlv(vb, p3)
            next_oid = _decode_oid(oid_val)
            if next_oid == oid or not (next_oid == base_oid or next_oid.startswith(base_oid + ".")):
                break
            results.append((next_oid, tag, val))
            oid = next_oid
    except Exception:
        pass
    finally:
        s.close()
    return results


# ======================================================================
#  Топология через SNMP: LLDP-соседи коммутаторов + MAC-таблицы портов
# ======================================================================

SYSNAME_OID = "1.3.6.1.2.1.1.5.0"
LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"   # BRIDGE/LLDP-MIB: имя соседнего устройства
FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"             # dot1dTpFdbPort: MAC (в OID) -> номер порта


def build_snmp_topology(seed_ips, community="public", hosts=None, max_switches=12, timeout=1.2):
    """BFS по управляемым коммутаторам, начиная с seed_ips: на каждом
    опрашивает LLDP-соседей (другие коммутаторы/точки доступа, становятся
    новыми узлами обхода) и таблицу MAC-адресов за портами (конечные
    устройства - камеры, ПК и т.п., листья дерева). hosts - список уже
    отсканированных узлов (ip/mac/vendor/device_type) для подписи листьев
    по IP/типу устройства вместо голого MAC, если он там засветился."""
    hosts = hosts or []
    mac_index = {h["mac"].lower(): h for h in hosts if h.get("mac")}
    nodes, edges, errors = {}, [], []
    visited = set()
    queue_ = list(dict.fromkeys(s.strip() for s in seed_ips if s.strip()))

    while queue_ and len(visited) < max_switches:
        sw_ip = queue_.pop(0)
        if sw_ip in visited:
            continue
        visited.add(sw_ip)
        sysname = snmp_get(sw_ip, oid=SYSNAME_OID, community=community, timeout=timeout)
        key = f"sw:{sw_ip}"
        nodes[key] = {"label": f"{sysname or sw_ip}\n{sw_ip}", "type": "router", "ip": sw_ip}

        rem = snmp_walk(sw_ip, LLDP_REM_SYSNAME, community, timeout)
        if not rem:
            errors.append(f"{sw_ip}: LLDP-соседи не получены (SNMP/LLDP выключен или не поддерживается)")
        for _oid, tag, val in rem:
            name = val.decode(errors="ignore").strip() if tag == 0x04 else ""
            if not name:
                continue
            nkey = f"name:{name}"
            if nkey not in nodes:
                nodes[nkey] = {"label": name, "type": "router"}
            edges.append((key, nkey, "LLDP"))
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", name) and name not in visited:
                queue_.append(name)

        fdb = snmp_walk(sw_ip, FDB_PORT, community, timeout)
        if not fdb:
            errors.append(f"{sw_ip}: таблица MAC-адресов не получена (SNMP выключен/community неверный)")
        prefix = FDB_PORT + "."
        for oid, tag, val in fdb:
            if tag != 0x02 or not oid.startswith(prefix):
                continue
            try:
                mac = ":".join(f"{int(x):02x}" for x in oid[len(prefix):].split("."))
            except ValueError:
                continue
            port = int.from_bytes(val, "big")
            h = mac_index.get(mac)
            vendor = (h or {}).get("vendor") or mac_vendor(mac)
            shown = (h or {}).get("ip") or mac
            hkey = f"host:{mac}"
            nodes[hkey] = {
                "label": "\n".join(x for x in (vendor, shown) if x),
                "type": _type_key((h or {}).get("device_type", "")),
                "mac": mac, "ip": (h or {}).get("ip"),
            }
            edges.append((key, hkey, f"порт {port}"))

    return {"nodes": nodes, "edges": edges, "errors": errors}


# ======================================================================
#  Пассивное прослушивание LLDP/CDP (scapy) - третий способ топологии,
#  не требующий SNMP-доступа к коммутатору: сам коммутатор каждые ~30 сек
#  рассылает кадры LLDP (мультикаст 01:80:c2:00:00:0e) и/или CDP (Cisco,
#  мультикаст 01:00:0c:cc:cc:cc) со своим именем/портом - мы их просто
#  слушаем. Требует прав администратора/root (сырые сокеты) и, на Windows,
#  установленного Npcap.
# ======================================================================

LLDP_MCAST = "01:80:c2:00:00:0e"
CDP_MCAST = "01:00:0c:cc:cc:cc"

# ----------------------------------------------------------------------
#  Npcap: обнаружение и установка «в один клик» прямо из приложения.
#
#  Npcap — системный драйвер ядра Windows, и его нельзя «вшить» в exe так,
#  чтобы он просто заработал без установки: Windows требует, чтобы такие
#  драйверы были явно установлены (и подписаны) в систему. Но сам
#  установщик Npcap можно встроить в сборку (--add-data в build.yml) и
#  запускать его прямо из приложения, когда он нужен — пользователю не
#  нужно самому идти на npcap.com и скачивать его отдельно, достаточно
#  один раз подтвердить запрос UAC.
# ----------------------------------------------------------------------

def npcap_installed():
    """True, если на машине уже установлен Npcap (или совместимый WinPcap)."""
    if not IS_WIN:
        return True  # на Linux/macOS достаточно root, см. has_sniff_privileges
    sysdir = os.environ.get("SystemRoot", r"C:\Windows")
    for p in (os.path.join(sysdir, "System32", "Npcap", "wpcap.dll"),
              os.path.join(sysdir, "System32", "Npcap", "Packet.dll"),
              os.path.join(sysdir, "System32", "wpcap.dll")):      # старый WinPcap/совместимый режим
        if os.path.isfile(p):
            return True
    try:
        import winreg
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap")
        return True
    except Exception:
        return False


def bundled_npcap_installer_path():
    """Путь к установщику Npcap, встроенному в сборку через --add-data
    (см. build.yml). Работает и из исходников (assets/рядом с файлом), и
    из собранного PyInstaller-exe (sys._MEIPASS). None, если не найден —
    тогда предложите пользователю скачать Npcap с npcap.com вручную."""
    bases = []
    if getattr(sys, "frozen", False):
        bases.append(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)))
        bases.append(os.path.dirname(sys.executable))
    bases.append(os.path.dirname(os.path.abspath(__file__)))
    for base in bases:
        p = os.path.join(base, "assets", "npcap-installer.exe")
        if os.path.isfile(p):
            return p
    return None


def install_npcap():
    """Запускает встроенный установщик Npcap с запросом прав администратора
    (UAC) и тихой установкой (/S). Блокирует вызывающий поток до завершения
    установки — вызывайте из фонового потока, не из главного цикла Tk.
    Возвращает (ok: bool, message: str)."""
    if not IS_WIN:
        return False, "Установка Npcap нужна только на Windows."
    installer = bundled_npcap_installer_path()
    if not installer:
        return False, ("Установщик Npcap не найден внутри приложения. "
                        "Скачайте и установите его вручную: https://npcap.com/#download")
    try:
        # ShellExecuteW с verb="runas" сам показывает диалог UAC; /S - тихая
        # установка после того, как пользователь подтвердит повышение прав.
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", installer, "/S", None, 1)
        if rc <= 32:   # ShellExecute возвращает <=32 при ошибке (см. документацию WinAPI)
            if rc == 5:
                return False, "Установка отменена: нужно подтвердить запрос администратора (UAC)."
            return False, f"Не удалось запустить установщик Npcap (код {rc})."
    except Exception as e:
        return False, f"Не удалось запустить установщик Npcap: {e}"
    # ShellExecute не блокирует и не даёт хэндл процесса - ждём появления
    # файла драйвера как признака завершения (silent-установка обычно
    # укладывается в несколько секунд).
    import time
    deadline = time.time() + 60
    while time.time() < deadline:
        if npcap_installed():
            return True, "Npcap установлен."
        time.sleep(1)
    return False, ("Установщик запущен, но Npcap пока не обнаружен — возможно, установка "
                   "ещё идёт или была закрыта. Проверьте и повторите при необходимости.")


def has_sniff_privileges():
    """True, если процесс, похоже, может открывать сырые сокеты для sniff()
    (admin на Windows, root/CAP_NET_RAW на Linux/macOS). Это эвристика для
    предупреждения пользователю ДО попытки прослушивания, а не гарантия —
    реальная ошибка всё равно перехватывается в build_passive_topology."""
    try:
        if IS_WIN:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False


def build_passive_topology(iface=None, duration=60, hosts=None, on_progress=None):
    """Слушает эфир duration секунд через scapy и собирает кадры LLDP/CDP,
    которые управляемые коммутаторы и некоторые другие устройства рассылают
    сами, без какого-либо SNMP-опроса. iface=None - интерфейс по умолчанию
    (как у scapy). hosts - уже отсканированные узлы (для подписи по IP/типу
    устройства там, где в кадре встретился MAC, который уже видели по ARP).
    Возвращает тот же формат {"nodes","edges","errors"}, что и у
    build_local_topology/build_snmp_topology.

    Требует прав администратора/root и, на Windows, Npcap — при их
    отсутствии (или отсутствии scapy) возвращает пустой результат с
    понятным пояснением в errors, а не падает и не роняет приложение."""
    nodes, edges, errors = {}, [], []

    if not SCAPY_AVAILABLE:
        errors.append("scapy не установлен (pip install scapy) — пассивное "
                       "прослушивание LLDP/CDP недоступно.")
        return {"nodes": nodes, "edges": edges, "errors": errors}

    if not has_sniff_privileges():
        errors.append("Нет прав администратора/root — сырые сокеты для прослушивания "
                       "LLDP/CDP недоступны. Запустите приложение от имени "
                       "администратора (Windows) или через sudo (Linux/macOS)."
                       + (" На Windows дополнительно нужен установленный Npcap." if IS_WIN else ""))
        return {"nodes": nodes, "edges": edges, "errors": errors}

    hosts = hosts or []
    mac_index = {h["mac"].lower(): h for h in hosts if h.get("mac")}
    me = "me"
    nodes[me] = {"label": "Этот компьютер", "type": "me"}

    try:
        from scapy.contrib.lldp import (
            LLDPDU, LLDPDUChassisID, LLDPDUPortID, LLDPDUSystemName)
    except Exception:
        LLDPDU = LLDPDUChassisID = LLDPDUPortID = LLDPDUSystemName = None
    try:
        from scapy.contrib.cdp import CDPMsgDeviceID, CDPMsgPortID
    except Exception:
        CDPMsgDeviceID = CDPMsgPortID = None

    seen_count = {"lldp": 0, "cdp": 0}

    def handle(pkt):
        try:
            src_mac = getattr(pkt, "src", "") or ""
            if LLDPDU is not None and pkt.haslayer(LLDPDU):
                seen_count["lldp"] += 1
                sysname = ""
                if pkt.haslayer(LLDPDUSystemName):
                    sysname = pkt[LLDPDUSystemName].system_name.decode(errors="ignore") \
                        if isinstance(pkt[LLDPDUSystemName].system_name, bytes) \
                        else str(pkt[LLDPDUSystemName].system_name)
                portid = ""
                if pkt.haslayer(LLDPDUPortID):
                    raw = pkt[LLDPDUPortID].id
                    portid = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
                label = sysname or src_mac
                key = f"lldp:{src_mac}"
                h = mac_index.get(src_mac.lower())
                if h:
                    label = f"{label}\n{h.get('ip', '')}" if h.get("ip") else label
                nodes[key] = {"label": label + (f"\nпорт {portid}" if portid else ""), "type": "router",
                             "mac": src_mac}
                edges.append((me, key, "LLDP"))
            elif CDPMsgDeviceID is not None and pkt.haslayer(CDPMsgDeviceID):
                seen_count["cdp"] += 1
                device_id = pkt[CDPMsgDeviceID].val
                device_id = device_id.decode(errors="ignore") if isinstance(device_id, bytes) else str(device_id)
                portid = ""
                if pkt.haslayer(CDPMsgPortID):
                    raw = pkt[CDPMsgPortID].val
                    portid = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
                key = f"cdp:{src_mac}"
                nodes[key] = {"label": (device_id or src_mac) + (f"\nпорт {portid}" if portid else ""),
                             "type": "router", "mac": src_mac}
                edges.append((me, key, "CDP"))
        except Exception:
            pass  # один повреждённый/непонятный кадр не должен рвать весь захват
        if on_progress:
            try:
                on_progress(seen_count["lldp"] + seen_count["cdp"])
            except Exception:
                pass

    bpf = f"ether dst {LLDP_MCAST} or ether dst {CDP_MCAST}"
    try:
        sniff(iface=iface, filter=bpf, prn=handle, store=False, timeout=max(5, duration))
    except PermissionError:
        errors.append("Нет прав на открытие сырого сокета (PermissionError) — запустите от "
                       "имени администратора/root.")
    except OSError as e:
        hint = " Проверьте, что установлен Npcap (npcap.com)." if IS_WIN else ""
        errors.append(f"Ошибка прослушивания сети: {e}.{hint}")
    except Exception as e:
        errors.append(f"Не удалось запустить прослушивание LLDP/CDP: {e}")

    if not errors and seen_count["lldp"] == 0 and seen_count["cdp"] == 0:
        errors.append("За время прослушивания не поймано ни одного кадра LLDP/CDP — "
                       "либо коммутатор их не рассылает (LLDP/CDP выключен), либо кадры "
                       "не доходят до этого интерфейса (другой VLAN/порт без зеркалирования), "
                       "либо нужно подождать дольше (коммутаторы рассылают их раз в ~30 сек).")

    return {"nodes": nodes, "edges": edges, "errors": errors}


# ======================================================================
#  Раскладка (простое многоуровневое дерево) и экспорт в Graphviz DOT
# ======================================================================

def layout(nodes, edges, root=None, spacing_x=170, spacing_y=110):
    """Простая многоуровневая раскладка через BFS от root (по умолчанию -
    первый узел): уровень = расстояние от корня, внутри уровня узлы стоят
    в ряд. Не настоящий алгоритм укладки графа без пересечений, но для
    сетевой топологии (в целом дерево от коммутатора/компьютера к листьям)
    даёт читаемую картинку."""
    adj = {}
    for e in edges:
        a, b = e[0], e[1]
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)
    all_keys = list(nodes.keys())
    if not all_keys:
        return {}
    if root is None or root not in nodes:
        root = all_keys[0]

    levels, visited, order = {}, set(), []
    queue_ = [(root, 0)]
    visited.add(root)
    while queue_:
        node, lvl = queue_.pop(0)
        levels.setdefault(lvl, []).append(node)
        order.append(node)
        for nb in sorted(adj.get(node, ())):
            if nb not in visited:
                visited.add(nb)
                queue_.append((nb, lvl + 1))
    rest = [k for k in all_keys if k not in visited]
    if rest:
        levels.setdefault((max(levels) + 1) if levels else 0, []).extend(rest)

    pos = {}
    for lvl, keys in levels.items():
        n = len(keys)
        for i, k in enumerate(keys):
            pos[k] = ((i - (n - 1) / 2) * spacing_x, lvl * spacing_y)
    return pos


def export_dot(topo, title="network"):
    """Текст в формате Graphviz DOT - открывается через `dot -Tpng in.dot -o
    out.png` (пакет graphviz) или онлайн, например на
    https://dreampuf.github.io/GraphvizOnline/."""
    def esc(s):
        return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    lines = [f'graph "{esc(title)}" {{', '  rankdir=LR;',
             '  node [shape=box, style=filled, fontname="Arial", fontsize=10];']
    for key, n in topo["nodes"].items():
        color = NODE_COLORS.get(n.get("type", "unknown"), "#cccccc")
        lines.append(f'  "{esc(key)}" [label="{esc(n.get("label", key))}", fillcolor="{color}"];')
    for e in topo["edges"]:
        a, b = e[0], e[1]
        elabel = e[2] if len(e) > 2 else ""
        attr = f' [label="{esc(elabel)}", fontsize=8]' if elabel else ""
        lines.append(f'  "{esc(a)}" -- "{esc(b)}"{attr};')
    lines.append("}")
    return "\n".join(lines)
