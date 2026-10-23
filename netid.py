"""
netid.py - определение устройств в локальной сети: MAC/OUI-вендор, догадка ОС
по TTL, NetBIOS-имя, SNMP sysDescr, SSDP/UPnP, mDNS/Bonjour, HTTP-баннер и
итоговый тип узла.

Только пассивные/безопасные запросы (то, что узел и так сообщает любому).
Использовать для диагностики своей сети или сети, на проверку которой есть
явное разрешение.

Публичный API (используется netscan.py, netsuite.py, topology.py):
    read_arp_table() -> {ip: mac}
    local_ip() -> str | None
    default_gateway() -> str | None
    mac_vendor(mac) -> str
    snmp_get(ip, oid=..., community="public", timeout=1.0) -> str | None
    ssdp_discover(timeout=3.0) -> {ip: {"server": str, "st": str, "location": str}}
    mdns_discover(timeout=3.0) -> {ip: {"services": [str, ...]}}
    identify_host(ip, ports, mac=None, timeout=1.0) -> dict
"""
import platform
import re
import socket
import struct
import subprocess
import time

# ----------------------------------------------------------------------
#  Вспомогательное
# ----------------------------------------------------------------------

_IS_WIN = platform.system() == "Windows"
_NOWINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if _IS_WIN else 0


def _run(cmd, timeout=5):
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout,
                             creationflags=_NOWINDOW)
        raw = out.stdout or b""
    except (OSError, subprocess.SubprocessError):
        return ""
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _norm_mac(mac):
    m = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(m) != 12:
        return ""
    m = m.lower()
    return ":".join(m[i:i + 2] for i in range(0, 12, 2))


# ----------------------------------------------------------------------
#  ARP, локальный IP, шлюз
# ----------------------------------------------------------------------

def read_arp_table():
    """Системная ARP-таблица: {ip: mac}. Без сетевых запросов."""
    table = {}
    text = _run(["arp", "-a"]) if _IS_WIN else (_run(["ip", "neigh"]) or _run(["arp", "-an"]))
    for line in text.splitlines():
        ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac_m = re.search(r"\b([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b", line)
        if not ip_m or not mac_m:
            continue
        mac = _norm_mac(mac_m.group(1))
        if not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        ip = ip_m.group(1)
        if ip.startswith(("224.", "239.", "255.")) or ip.endswith(".255"):
            continue
        table[ip] = mac
    return table


def local_ip():
    """IP этого компьютера в основной сети (без отправки пакетов)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return None
    finally:
        s.close()


def default_gateway():
    """IP шлюза по умолчанию или None."""
    if _IS_WIN:
        text = _run(["route", "print", "-4", "0.0.0.0"])
        for line in text.splitlines():
            p = line.split()
            if len(p) >= 3 and p[0] == "0.0.0.0" and p[1] == "0.0.0.0":
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", p[2]):
                    return p[2]
        return None
    text = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\d{1,3}(?:\.\d{1,3}){3})", text)
    if m:
        return m.group(1)
    text = _run(["route", "-n"])
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 2 and p[0] == "0.0.0.0":
            return p[1]
    return None


# ----------------------------------------------------------------------
#  OUI -> вендор (компактная таблица самых частых производителей)
# ----------------------------------------------------------------------

_OUI = {
    "00:0c:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM", "00:15:5d": "Microsoft Hyper-V",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "28:cd:c1": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi",
    "00:1a:11": "Google", "f4:f5:d8": "Google", "3c:5a:b4": "Google", "a4:77:33": "Google",
    "fc:65:de": "Amazon", "44:65:0d": "Amazon", "68:54:fd": "Amazon", "74:c2:46": "Amazon",
    "f0:18:98": "Apple", "3c:07:54": "Apple", "a4:5e:60": "Apple", "d0:03:4b": "Apple",
    "ac:de:48": "Apple", "00:1c:b3": "Apple", "00:03:93": "Apple", "f8:1e:df": "Apple",
    "00:16:cb": "Apple", "88:66:a5": "Apple", "70:56:81": "Apple",
    "00:16:32": "Samsung", "5c:0a:5b": "Samsung", "78:47:1d": "Samsung", "cc:07:ab": "Samsung",
    "00:12:fb": "Samsung", "e8:50:8b": "Samsung",
    "00:1b:63": "Apple", "00:25:00": "Apple",
    "00:0e:08": "Cisco-Linksys", "00:1d:7e": "Cisco-Linksys", "00:40:96": "Cisco",
    "00:1e:13": "Cisco", "00:1b:54": "Cisco", "00:0f:23": "Cisco", "f8:72:ea": "Cisco",
    "00:18:0a": "Cisco Meraki", "e0:55:3d": "Cisco Meraki",
    "00:0b:86": "Aruba", "00:1a:1e": "Aruba", "24:de:c6": "Aruba",
    "00:1f:a4": "Huawei", "00:e0:fc": "Huawei", "28:6e:d4": "Huawei", "48:46:fb": "Huawei",
    "00:25:9e": "Huawei", "ac:e2:15": "Huawei",
    "00:0f:e2": "H3C", "00:23:89": "H3C",
    "00:90:4c": "Epigram/Broadcom", "00:10:18": "Broadcom",
    "00:14:78": "TP-Link", "50:c7:bf": "TP-Link", "ec:08:6b": "TP-Link", "14:cc:20": "TP-Link",
    "f4:f2:6d": "TP-Link", "98:da:c4": "TP-Link", "a4:2b:b0": "TP-Link", "c0:06:c3": "TP-Link",
    "00:0a:eb": "TP-Link", "d8:0d:17": "TP-Link",
    "00:1b:11": "D-Link", "00:17:9a": "D-Link", "1c:7e:e5": "D-Link", "28:10:7b": "D-Link",
    "00:22:b0": "D-Link", "c8:be:19": "D-Link",
    "00:0c:42": "MikroTik", "4c:5e:0c": "MikroTik", "6c:3b:6b": "MikroTik", "e4:8d:8c": "MikroTik",
    "b8:69:f4": "MikroTik", "cc:2d:e0": "MikroTik", "d4:ca:6d": "MikroTik",
    "00:09:5b": "Netgear", "00:1b:2f": "Netgear", "a0:63:91": "Netgear", "c0:3f:0e": "Netgear",
    "00:0f:b5": "Netgear", "20:e5:2a": "Netgear",
    "00:1d:60": "ASUSTeK", "04:d4:c4": "ASUSTeK", "2c:fd:a1": "ASUSTeK", "50:46:5d": "ASUSTeK",
    "f4:6d:04": "ASUSTeK", "08:60:6e": "ASUSTeK",
    "00:11:32": "Synology", "00:08:9b": "QNAP", "24:5e:be": "QNAP",
    "00:0d:b9": "PC Engines", "00:e0:4c": "Realtek", "52:54:ab": "Realtek",
    "00:1f:3c": "Intel", "00:1b:21": "Intel", "3c:97:0e": "Intel", "a4:4c:c8": "Intel",
    "00:13:20": "Intel", "00:1e:64": "Intel", "f8:63:3f": "Intel",
    "00:23:24": "G.Skill/Gigabyte", "1c:1b:0d": "Gigabyte", "00:1f:d0": "Gigabyte",
    "00:1a:a0": "Dell", "00:14:22": "Dell", "f8:bc:12": "Dell", "b8:ac:6f": "Dell",
    "00:1e:c9": "Dell", "d4:be:d9": "Dell",
    "00:1e:0b": "HP", "00:21:5a": "HP", "3c:d9:2b": "HP", "9c:b6:54": "HP", "00:17:08": "HP",
    "00:25:b3": "HP", "10:1f:74": "HP", "00:30:c1": "HP",
    "00:00:48": "Epson", "00:26:ab": "Epson", "64:eb:8c": "Epson",
    "00:00:85": "Canon", "00:1e:8f": "Canon", "18:0c:ac": "Canon",
    "00:80:77": "Brother", "00:1b:a9": "Brother", "30:05:5c": "Brother",
    "00:0e:7f": "HP", "00:00:aa": "Xerox", "00:00:74": "Ricoh", "00:26:73": "Ricoh",
    "00:12:17": "Cisco-Linksys",
    "00:40:8c": "Axis", "ac:cc:8e": "Axis", "b8:a4:4f": "Axis", "00:40:8d": "Axis",
    "00:0f:7c": "ACTi", "00:30:53": "Basler",
    "bc:ad:28": "Hikvision", "c0:56:e3": "Hikvision", "44:19:b6": "Hikvision",
    "28:57:be": "Hikvision", "4c:11:bf": "Hikvision", "a4:14:37": "Hikvision",
    "54:c4:15": "Hikvision", "18:68:cb": "Hikvision", "c4:2f:90": "Hikvision",
    "3c:ef:8c": "Dahua", "90:02:a9": "Dahua", "9c:8e:cd": "Dahua", "e0:50:8b": "Dahua",
    "4c:bd:8f": "Dahua", "38:af:29": "Dahua", "bc:32:5f": "Dahua",
    "00:1c:27": "Sunell", "00:12:12": "Plustek",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
    "18:b4:30": "Nest", "64:16:66": "Nest",
    "b0:be:76": "TP-Link", "5c:cf:7f": "Espressif (ESP8266)", "24:0a:c4": "Espressif",
    "30:ae:a4": "Espressif", "84:0d:8e": "Espressif", "a4:cf:12": "Espressif",
    "60:01:94": "Espressif", "ac:67:b2": "Espressif", "10:52:1c": "Espressif",
    "d8:a0:1d": "Espressif", "ec:fa:bc": "Espressif", "bc:dd:c2": "Espressif",
    "7c:df:a1": "Espressif", "cc:50:e3": "Espressif",
    "00:04:20": "Slim Devices", "00:0e:58": "Sonos", "5c:aa:fd": "Sonos", "b8:e9:37": "Sonos",
    "78:28:ca": "Sonos", "00:0d:4b": "Roku", "b0:a7:37": "Roku", "cc:6d:a0": "Roku",
    "00:1a:79": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:d6": "Ubiquiti", "24:a4:3c": "Ubiquiti",
    "44:d9:e7": "Ubiquiti", "68:72:51": "Ubiquiti", "78:8a:20": "Ubiquiti", "80:2a:a8": "Ubiquiti",
    "dc:9f:db": "Ubiquiti", "f0:9f:c2": "Ubiquiti", "fc:ec:da": "Ubiquiti", "b4:fb:e4": "Ubiquiti",
    "00:1d:aa": "DrayTek", "00:50:7f": "DrayTek", "14:49:bc": "DrayTek",
    "00:04:23": "Intel", "00:0e:c6": "ASIX", "00:19:99": "Fujitsu",
    "00:13:77": "Samsung", "00:07:ab": "Samsung",
    "00:1e:58": "D-Link", "00:21:91": "D-Link", "00:24:01": "D-Link",
    "00:1f:33": "Netgear", "00:24:b2": "Netgear", "00:26:f2": "Netgear",
    "00:50:f2": "Microsoft", "28:18:78": "Microsoft", "7c:1e:52": "Microsoft",
    "00:0d:3a": "Microsoft", "00:17:fa": "Microsoft", "60:45:bd": "Microsoft",
    "00:1d:d8": "Microsoft", "98:5f:d3": "Microsoft",
    "00:04:4b": "NVIDIA", "00:0a:e4": "Wistron", "00:1c:23": "Dell",
    "54:60:09": "Google", "f8:8f:ca": "Google", "20:df:b9": "Google", "48:d6:d5": "Google",
    "cc:f4:11": "Google", "30:fd:38": "Google",
    "08:00:20": "Oracle/Sun", "00:a0:c9": "Intel", "00:02:b3": "Intel",
    "00:11:11": "Intel", "00:15:17": "Intel", "00:16:76": "Intel", "00:19:d1": "Intel",
    "00:1c:c0": "Intel", "00:21:6a": "Intel", "00:22:fb": "Intel", "00:24:d7": "Intel",
    "00:27:10": "Intel", "40:25:c2": "Intel", "48:51:b7": "Intel", "5c:51:4f": "Intel",
    "60:57:18": "Intel", "68:05:ca": "Intel", "7c:5c:f8": "Intel", "80:19:34": "Intel",
    "88:53:2e": "Intel", "94:65:9c": "Intel", "a0:36:9f": "Intel", "b4:b6:76": "Intel",
}


def mac_vendor(mac):
    """Производитель по OUI (локальная таблица). '' если неизвестно."""
    m = _norm_mac(mac)
    if not m:
        return ""
    first = int(m[:2], 16)
    if first & 0x02:
        return "(случайный/локальный MAC)"
    return _OUI.get(m[:8], "")


# ----------------------------------------------------------------------
#  ОС по TTL (через системный ping)
# ----------------------------------------------------------------------

def _ping_ttl(ip, timeout=1.0):
    if _IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), ip]
    text = _run(cmd, timeout=timeout + 3)
    m = re.search(r"ttl[=:\s]+(\d+)", text, re.I)
    return int(m.group(1)) if m else None


def _os_from_ttl(ttl):
    if ttl is None:
        return ""
    if ttl <= 64:
        return "Linux/Unix/Android/IoT (TTL≈64)"
    if ttl <= 128:
        return "Windows (TTL≈128)"
    return "Сетевое оборудование/Cisco/Solaris (TTL≈255)"


# ----------------------------------------------------------------------
#  NetBIOS-имя (UDP 137)
# ----------------------------------------------------------------------

def _netbios_name(ip, timeout=1.0):
    query = (b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(1024)
    except OSError:
        return ""
    finally:
        s.close()
    try:
        count = data[56]
        if count < 1:
            return ""
        return data[57:72].decode("ascii", "ignore").strip()
    except IndexError:
        return ""


# ----------------------------------------------------------------------
#  SNMP v2c GET (минимальный BER)
# ----------------------------------------------------------------------

SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"


def _ber_len(n):
    if n < 128:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def _tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def _enc_oid(oid):
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


def _read_tlv(data, pos):
    tag = data[pos]
    ln = data[pos + 1]
    pos += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, data[pos:pos + ln], pos + ln


def snmp_get(ip, oid=SYSDESCR_OID, community="public", timeout=1.0):
    """SNMP v2c GET одного OID. Возвращает строку или None."""
    varbind = _tlv(0x30, _tlv(0x06, _enc_oid(oid)) + _tlv(0x05, b""))
    pdu = _tlv(0xA0,
               _tlv(0x02, b"\x01\x23") +      # request-id
               _tlv(0x02, b"\x00") +          # error-status
               _tlv(0x02, b"\x00") +          # error-index
               _tlv(0x30, varbind))
    msg = _tlv(0x30, _tlv(0x02, b"\x01") +    # version: v2c
               _tlv(0x04, community.encode()) + pdu)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (ip, 161))
        data, _ = s.recvfrom(4096)
    except OSError:
        return None
    finally:
        s.close()
    try:
        _, body, _ = _read_tlv(data, 0)               # SEQUENCE
        _, _, p = _read_tlv(body, 0)                  # version
        _, _, p = _read_tlv(body, p)                  # community
        _, pdu_body, _ = _read_tlv(body, p)           # response PDU
        _, _, p = _read_tlv(pdu_body, 0)              # request-id
        _, err, p = _read_tlv(pdu_body, p)            # error-status
        if int.from_bytes(err, "big") != 0:
            return None
        _, _, p = _read_tlv(pdu_body, p)              # error-index
        _, vbl, _ = _read_tlv(pdu_body, p)            # varbind list
        _, vb, _ = _read_tlv(vbl, 0)                  # varbind
        _, _, p = _read_tlv(vb, 0)                    # oid
        tag, val, _ = _read_tlv(vb, p)
    except (IndexError, ValueError):
        return None
    if tag == 0x04:
        return val.decode("utf-8", "replace").strip()
    if tag == 0x02:
        return str(int.from_bytes(val, "big", signed=True))
    return None


# ----------------------------------------------------------------------
#  SSDP / UPnP
# ----------------------------------------------------------------------

def ssdp_discover(timeout=3.0):
    """M-SEARCH по мультикасту. Возвращает {ip: {server, st, location}}."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(0.5)
    try:
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            hdr = {}
            for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdr[k.strip().lower()] = v.strip()
            rec = found.setdefault(addr[0], {"server": "", "st": "", "location": ""})
            rec["server"] = rec["server"] or hdr.get("server", "")
            rec["st"] = rec["st"] or hdr.get("st", "")
            rec["location"] = rec["location"] or hdr.get("location", "")
    except OSError:
        pass
    finally:
        s.close()
    return found


# ----------------------------------------------------------------------
#  mDNS / Bonjour
# ----------------------------------------------------------------------

_MDNS_SERVICES = [
    "_services._dns-sd._udp.local", "_airplay._tcp.local", "_raop._tcp.local",
    "_googlecast._tcp.local", "_ipp._tcp.local", "_printer._tcp.local",
    "_http._tcp.local", "_hap._tcp.local", "_homekit._tcp.local",
    "_smb._tcp.local", "_afpovertcp._tcp.local", "_ssh._tcp.local",
    "_spotify-connect._tcp.local", "_companion-link._tcp.local",
    "_workstation._tcp.local", "_rtsp._tcp.local", "_nvstream._tcp.local",
]


def _dns_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _read_name(data, pos):
    labels, jumped, end = [], False, pos
    guard = 0
    while guard < 64:
        guard += 1
        if pos >= len(data):
            break
        ln = data[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = ptr
            continue
        pos += 1
        labels.append(data[pos:pos + ln].decode("utf-8", "replace"))
        pos += ln
    if not jumped:
        end = pos
    return ".".join(labels), end


def _parse_mdns(data):
    """Возвращает список имён сервисов (PTR-записи) из ответа."""
    names = []
    try:
        qd, an, ns, ar = struct.unpack(">4H", data[4:12])
        pos = 12
        for _ in range(qd):
            _, pos = _read_name(data, pos)
            pos += 4
        for _ in range(an + ns + ar):
            name, pos = _read_name(data, pos)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 12:  # PTR
                target, _ = _read_name(data, pos)
                names.append(name)
                names.append(target)
            pos += rdlen
    except (struct.error, IndexError):
        pass
    return names


def mdns_discover(timeout=3.0):
    """Мультикаст-запрос популярных Bonjour-сервисов. {ip: {services: [..]}}."""
    pkt = struct.pack(">6H", 0, 0, len(_MDNS_SERVICES), 0, 0, 0)
    for svc in _MDNS_SERVICES:
        pkt += _dns_name(svc) + struct.pack(">HH", 12, 0x8001)  # PTR, QU
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.settimeout(0.5)
    try:
        s.sendto(pkt, ("224.0.0.251", 5353))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            svcs = found.setdefault(addr[0], {"services": []})
            for n in _parse_mdns(data):
                m = re.search(r"(_[a-z0-9-]+\._(?:tcp|udp))\.local", n)
                label = m.group(1) if m else ""
                if label and label not in svcs["services"] and label != "_services._dns-sd._udp":
                    svcs["services"].append(label)
    except OSError:
        pass
    finally:
        s.close()
    return found


# ----------------------------------------------------------------------
#  HTTP / баннеры
# ----------------------------------------------------------------------

def _http_probe(ip, port, timeout=1.0):
    """GET / по HTTP(S). Возвращает {server, title, auth, status} или {}."""
    import ssl
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        if port in (443, 8443, 8554, 322, 7443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            sock = raw
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netid/1.0\r\n"
                     f"Connection: close\r\n\r\n".encode())
        data = b""
        while len(data) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
    except (OSError, ssl.SSLError):
        return {}
    text = data.decode("utf-8", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    m = re.match(r"HTTP/\S+\s+(\d+)", lines[0]) if lines else None
    if not m:
        return {}
    hdr = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdr[k.strip().lower()] = v.strip()
    t = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return {
        "status": int(m.group(1)),
        "server": hdr.get("server", ""),
        "title": re.sub(r"\s+", " ", t.group(1)).strip()[:80] if t else "",
        "auth": hdr.get("www-authenticate", ""),
    }


def _banner(ip, port, timeout=1.0):
    """Читает приветствие сервиса (SSH/FTP/Telnet/SMTP...)."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            data = s.recv(256)
        finally:
            s.close()
    except OSError:
        return ""
    txt = data.decode("utf-8", "replace").strip().splitlines()
    return txt[0][:120] if txt else ""


# ----------------------------------------------------------------------
#  Итоговое определение узла
# ----------------------------------------------------------------------

_VENDOR_TYPES = [
    (("hikvision", "dahua", "axis", "acti", "sunell"), "IP-камера/видеорегистратор"),
    (("mikrotik", "tp-link", "d-link", "netgear", "asustek", "ubiquiti", "draytek",
      "cisco", "huawei", "h3c", "aruba", "linksys", "meraki"), "Роутер/коммутатор/точка доступа"),
    (("synology", "qnap"), "NAS (файловое хранилище)"),
    (("epson", "canon", "brother", "ricoh", "xerox"), "Принтер/МФУ"),
    (("espressif", "philips hue", "nest", "sonos", "roku", "amazon"), "IoT/умное устройство"),
    (("raspberry",), "Linux-устройство (Raspberry Pi)"),
    (("vmware", "virtualbox", "qemu", "hyper-v"), "Виртуальная машина"),
    (("apple",), "Устройство Apple"),
    (("samsung", "google"), "Смартфон/ТВ/IoT"),
]


def _guess_type(vendor, ports, os_guess, http, snmp_descr, ssdp_server, mdns):
    blob = " ".join([snmp_descr or "", ssdp_server or "", (http or {}).get("server", ""),
                     (http or {}).get("title", "")]).lower()
    ports = set(ports or [])
    if any(k in blob for k in ("camera", "ipcam", "hikvision", "dahua", "dvr", "nvr", "onvif")):
        return "IP-камера/видеорегистратор"
    if any(k in blob for k in ("router", "routeros", "mikrotik", "openwrt", "gateway", "switch",
                               "access point")):
        return "Роутер/коммутатор/точка доступа"
    if any(k in blob for k in ("synology", "qnap", "diskstation", "nas")):
        return "NAS (файловое хранилище)"
    if any(k in blob for k in ("printer", "laserjet", "officejet", "mfp")) or 9100 in ports \
            or 631 in ports or any("ipp" in s or "printer" in s for s in mdns or []):
        return "Принтер/МФУ"
    if 554 in ports or 8554 in ports:
        return "IP-камера/видеорегистратор"
    v = (vendor or "").lower()
    for keys, label in _VENDOR_TYPES:
        if any(k in v for k in keys):
            return label
    if 3389 in ports or 445 in ports or 135 in ports or "Windows" in (os_guess or ""):
        return "Windows ПК/сервер"
    if 22 in ports and "Linux" in (os_guess or ""):
        return "Linux сервер/устройство"
    if mdns:
        return "Устройство с mDNS/Bonjour"
    return ""


def identify_host(ip, ports, mac=None, timeout=1.0):
    """Собирает всё, что можно узнать о узле безопасными запросами.

    Возвращает dict: mac, vendor, os_guess, netbios, hostname, snmp, banner,
    http, device_type.
    """
    ports = list(ports or [])
    mac = _norm_mac(mac) if mac else read_arp_table().get(ip, "")
    vendor = mac_vendor(mac) if mac else ""
    os_guess = _os_from_ttl(_ping_ttl(ip, timeout))

    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        pass
    netbios = _netbios_name(ip, timeout) if (139 in ports or 445 in ports or not ports) else ""
    snmp_descr = snmp_get(ip, SYSDESCR_OID, timeout=timeout) if (161 in ports or not ports) else None

    http = {}
    for p in (80, 8080, 8000, 443, 8443):
        if p in ports:
            http = _http_probe(ip, p, timeout)
            if http:
                break

    banner = ""
    for p in (22, 21, 23, 25):
        if p in ports:
            banner = _banner(ip, p, timeout)
            if banner:
                break
    parts = []
    if banner:
        parts.append(banner)
    if snmp_descr:
        parts.append("SNMP: " + snmp_descr[:100])
    if http:
        h = " ".join(x for x in (http.get("server"), http.get("title")) if x)
        if h:
            parts.append("HTTP: " + h)
    banner_all = " | ".join(parts)

    device_type = _guess_type(vendor, ports, os_guess, http, snmp_descr, "", [])
    return {
        "mac": mac,
        "vendor": vendor,
        "os_guess": os_guess,
        "netbios": netbios,
        "hostname": hostname,
        "snmp": snmp_descr or "",
        "banner": banner_all,
        "http": http,
        "device_type": device_type,
    }
