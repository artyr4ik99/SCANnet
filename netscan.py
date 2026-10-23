#!/usr/bin/env python3
"""
netscan.py - консольный сканер своей сети: находит узлы, определяет, что это
за устройство (производитель, ОС, тип), и позволяет подключиться к найденному
узлу (SSH/Telnet/веб/RDP/raw TCP).

Используется ТОЛЬКО для диагностики собственной сети или сети, на проверку
которой у вас есть разрешение.

Использование:
    python netscan.py                      # автоопределение подсети (/24)
    python netscan.py 192.168.1.0/24
    python netscan.py 10.0.0.0/24 10.0.1.0/24 --timeout 0.5
    python netscan.py 192.168.1.0/24 --json out.json
    python netscan.py 192.168.1.0/24 --csv out.csv --no-identify
"""
import argparse
import csv
import datetime
import ipaddress
import json
import platform
import shutil
import socket
import subprocess
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor

import netid
import risk
import topology

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "netbios", 143: "imap", 161: "snmp", 443: "https",
    445: "smb", 548: "afp", 554: "rtsp", 631: "ipp", 1883: "mqtt",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 8554: "rtsp-alt",
    9100: "printer",
}
QUICK_PORTS = (22, 80, 443, 445, 3389)  # для быстрой проверки "живой/нет"
IS_WIN = platform.system() == "Windows"


# ---------- обнаружение ----------

def detect_local_network() -> str:
    """IP основного интерфейса (пакеты не отправляются), берёт /24."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def ping(ip: str) -> bool:
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "700", ip]
    elif platform.system() == "Darwin":
        cmd = ["ping", "-c", "1", "-W", "700", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolve_name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def probe(ip: str, timeout: float) -> dict:
    alive = ping(ip) or any(tcp_open(ip, p, timeout) for p in QUICK_PORTS)
    if not alive:
        return {"ip": ip, "alive": False}
    ports = [p for p in COMMON_PORTS if tcp_open(ip, p, timeout)]
    return {"ip": ip, "alive": True, "ports": ports, "name": resolve_name(ip)}


def scan(networks: list, timeout: float, workers: int) -> list:
    targets = []
    for n in networks:
        targets += [str(h) for h in ipaddress.ip_network(n, strict=False).hosts()]

    print(f"Сканирую {len(targets)} адресов...")
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = {r["ip"]: r for r in ex.map(lambda ip: probe(ip, timeout), targets)}

    # Узлы, блокирующие ping и наши порты, всё равно попадают в ARP
    arp = netid.read_arp_table()
    target_set = set(targets)
    for ip, mac in arp.items():
        if ip in target_set and not results[ip]["alive"]:
            results[ip] = {"ip": ip, "alive": True, "ports": [], "name": resolve_name(ip)}

    hosts = [r for r in results.values() if r["alive"]]
    for h in hosts:
        h["mac"] = arp.get(h["ip"], "")
    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return hosts


def identify_all(hosts: list, timeout: float, workers: int) -> None:
    print("Определяю тип устройств...")

    def one(h):
        d = netid.identify_host(h["ip"], h["ports"], mac=h.get("mac"), timeout=timeout)
        h.update(d)
        return h

    with ThreadPoolExecutor(max_workers=min(workers, 32)) as ex:
        list(ex.map(one, hosts))


def mdns_merge(hosts: list, timeout: float = 2.5) -> int:
    """Запускает netid.mdns_discover() и добавляет найденные mDNS-сервисы
    узлам из hosts (по IP), которых не было видно по SSDP/баннерам.
    Возвращает число узлов, у которых появилась mDNS-информация."""
    found = netid.mdns_discover(timeout)
    by_ip = {h["ip"]: h for h in hosts}
    touched = 0
    for ip, info in found.items():
        services = info.get("services") or []
        if ip in by_ip:
            h = by_ip[ip]
            h["mdns"] = services
            if services and not h.get("device_type"):
                h["device_type"] = "Устройство с mDNS/Bonjour"
            touched += 1
        else:
            # узел не попал под сканируемую подсеть напрямую (например,
            # ответил с другого интерфейса) - добавляем отдельной записью
            hosts.append({"ip": ip, "alive": True, "ports": [], "mac": "",
                          "name": "", "mdns": services,
                          "device_type": "Устройство с mDNS/Bonjour (вне скана портов)"})
            touched += 1
    return touched


def assess_all_risk(hosts: list, timeout: float = 2.5) -> None:
    """Проставляет каждому узлу host['risk'] = {"level":..., "reasons":[...]}."""
    print("Оцениваю риск узлов (открытые порты/баннеры/TLS)...")
    for h in hosts:
        h["risk"] = risk.assess_risk(h, timeout=timeout)


# ---------- журнал изменений (--watch) ----------

def _host_fingerprint(h: dict) -> dict:
    """Минимальный набор полей узла, по которым отслеживаются изменения
    между проходами сканирования."""
    return {
        "mac": h.get("mac", ""),
        "ports": sorted(h.get("ports", [])),
        "vendor": h.get("vendor", ""),
        "device_type": h.get("device_type", ""),
    }


def load_history(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"hosts": {}, "events": []}


def save_history(path: str, history: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)


def diff_and_update_history(hosts: list, history: dict) -> list:
    """Сравнивает текущий скан с сохранённой историей, возвращает список
    новых событий (строк) и обновляет history на месте (в т.ч. events)."""
    now = datetime.datetime.now().isoformat(timespec="seconds")
    prev_hosts = history.setdefault("hosts", {})
    events = history.setdefault("events", [])
    new_events = []
    seen_ips = set()

    for h in hosts:
        ip = h["ip"]
        seen_ips.add(ip)
        fp = _host_fingerprint(h)
        old = prev_hosts.get(ip)
        if old is None:
            new_events.append(f"[{now}] новый узел: {ip} ({fp['vendor'] or fp['device_type'] or '?'})")
        else:
            if old.get("mac") and fp["mac"] and old["mac"] != fp["mac"]:
                new_events.append(f"[{now}] у {ip} сменился MAC: {old['mac']} -> {fp['mac']}")
            if set(old.get("ports", [])) != set(fp["ports"]):
                added = sorted(set(fp["ports"]) - set(old.get("ports", [])))
                removed = sorted(set(old.get("ports", [])) - set(fp["ports"]))
                parts = []
                if added:
                    parts.append(f"открылись порты {added}")
                if removed:
                    parts.append(f"закрылись порты {removed}")
                if parts:
                    new_events.append(f"[{now}] у {ip} изменились порты: {', '.join(parts)}")
        prev_hosts[ip] = fp

    missing = set(prev_hosts.keys()) - seen_ips
    # узел считается пропавшим, только если он реально числился живым
    # в предыдущем проходе (а не был добавлен только что из mDNS и т.п.)
    for ip in sorted(missing):
        if prev_hosts[ip].get("_gone"):
            continue
        new_events.append(f"[{now}] узел пропал: {ip}")
        prev_hosts[ip]["_gone"] = True

    for ip in seen_ips:
        prev_hosts[ip].pop("_gone", None)

    events.extend(new_events)
    return new_events


def watch_loop(networks: list, args) -> None:
    """Режим --watch: пересканирует сеть раз в args.watch минут, сравнивает
    с сохранённой историей (--watch-log) и печатает/пишет события."""
    interval = max(args.watch, 1) * 60
    print(f"Режим наблюдения: пересканирование каждые {args.watch} мин. "
          f"Журнал: {args.watch_log}. Ctrl+C для выхода.")
    history = load_history(args.watch_log)
    try:
        while True:
            hosts = scan(networks, args.timeout, args.workers)
            if not args.no_identify and hosts:
                identify_all(hosts, max(args.timeout, 1.0), args.workers)
            if args.mdns:
                mdns_merge(hosts)
            if args.risk or args.risk_only:
                assess_all_risk(hosts)
            events = diff_and_update_history(hosts, history)
            save_history(args.watch_log, history)
            if events:
                for e in events:
                    print(e)
            else:
                print(f"[{datetime.datetime.now().isoformat(timespec='seconds')}] изменений нет "
                      f"({len(hosts)} узлов)")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nНаблюдение остановлено.")


# ---------- вывод и подключение ----------

def print_hosts(hosts: list, show_risk: bool = False) -> None:
    head = f"\n{'#':>3}  {'IP':<16} {'MAC':<18} {'Производитель':<16} {'Тип устройства':<24} Порты"
    if show_risk:
        head += "  Риск"
    print(head)
    for i, h in enumerate(hosts, 1):
        ports = ",".join(f"{p}/{COMMON_PORTS.get(p, p)}" for p in h["ports"]) or "-"
        vendor = h.get("vendor", "") or "-"
        dtype = h.get("device_type", "") or "-"
        line = f"{i:>3}  {h['ip']:<16} {h.get('mac') or '-':<18} {vendor[:15]:<16} {dtype[:23]:<24} {ports}"
        if show_risk:
            line += f"  {h.get('risk', {}).get('level', '-')}"
        print(line)
        name_bits = [x for x in (h.get("name"), h.get("hostname"), h.get("netbios")) if x]
        banner = h.get("banner", "")
        mdns = h.get("mdns") or []
        if name_bits or banner or mdns:
            extra = " / ".join(dict.fromkeys(name_bits))
            tail = " | ".join(x for x in (extra, banner, ("mDNS: " + ", ".join(mdns)) if mdns else "") if x)
            print(f"     {tail}")
        if show_risk and h.get("risk", {}).get("level") in ("средний", "высокий"):
            for reason in h["risk"]["reasons"]:
                print(f"       ! {reason}")


def raw_tcp(ip: str, port: int) -> None:
    """Минимальный netcat: вводите строки, видите ответ. Ctrl+C - выход."""
    with socket.create_connection((ip, port), timeout=3) as s:
        s.settimeout(1)
        print(f"Подключено к {ip}:{port}. Ctrl+C для выхода.")
        try:
            while True:
                try:
                    data = s.recv(4096)
                    if data:
                        print(data.decode(errors="replace"), end="")
                except socket.timeout:
                    pass
                line = input("> ")
                s.sendall((line + "\r\n").encode())
        except (KeyboardInterrupt, EOFError, OSError):
            print("\nОтключено.")


def connect(host: dict) -> None:
    ip, ports = host["ip"], host["ports"]
    actions = []  # (описание, функция)
    if 22 in ports and shutil.which("ssh"):
        actions.append(("SSH", lambda: subprocess.call(
            ["ssh", f"{input('Пользователь: ').strip()}@{ip}"])))
    if 23 in ports and shutil.which("telnet"):
        actions.append(("Telnet", lambda: subprocess.call(["telnet", ip])))
    for p, scheme in ((80, "http"), (8080, "http"), (443, "https"), (8443, "https")):
        if p in ports:
            actions.append((f"Открыть {scheme}://{ip}:{p} в браузере",
                            lambda s=scheme, p=p: webbrowser.open(f"{s}://{ip}:{p}")))
    if 3389 in ports:
        if IS_WIN:
            actions.append(("RDP (mstsc)", lambda: subprocess.call(["mstsc", f"/v:{ip}"])))
        elif shutil.which("xfreerdp"):
            actions.append(("RDP (xfreerdp)", lambda: subprocess.call(
                ["xfreerdp", f"/v:{ip}", f"/u:{input('Пользователь: ').strip()}"])))
    if 5900 in ports:
        for name in ("vncviewer", "vinagre", "remmina"):
            if shutil.which(name):
                actions.append((f"VNC ({name})", lambda n=name: subprocess.call([n, ip])))
                break
    for p in ports:
        actions.append((f"Сырое TCP-соединение к порту {p} ({COMMON_PORTS.get(p, '?')})",
                        lambda p=p: raw_tcp(ip, p)))
    actions.append(("Raw TCP на произвольный порт",
                    lambda: raw_tcp(ip, int(input("Порт: ")))))

    for i, (desc, _) in enumerate(actions, 1):
        print(f"  {i}. {desc}")
    choice = input("Действие (Enter - назад): ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(actions):
        actions[int(choice) - 1][1]()


def export(hosts: list, path: str) -> None:
    rows = [{
        "ip": h["ip"], "mac": h.get("mac", ""), "vendor": h.get("vendor", ""),
        "device_type": h.get("device_type", ""), "os_guess": h.get("os_guess", ""),
        "hostname": h.get("hostname") or h.get("name", ""),
        "ports": ",".join(map(str, h.get("ports", []))), "banner": h.get("banner", ""),
        "mdns": ", ".join(h.get("mdns") or []),
        "risk_level": h.get("risk", {}).get("level", ""),
        "risk_reasons": "; ".join(h.get("risk", {}).get("reasons", [])),
    } for h in hosts]
    fieldnames = ["ip", "mac", "vendor", "device_type", "os_guess", "hostname",
                  "ports", "banner", "mdns", "risk_level", "risk_reasons"]
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
    else:
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)
    print(f"Экспортировано в {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Сканер собственной сети с определением устройств")
    ap.add_argument("networks", nargs="*", help="CIDR-подсети, напр. 192.168.1.0/24")
    ap.add_argument("--timeout", type=float, default=0.4, help="таймаут TCP, сек")
    ap.add_argument("--workers", type=int, default=128, help="число потоков")
    ap.add_argument("--no-identify", action="store_true",
                    help="не определять производителя/тип устройства (только порты)")
    ap.add_argument("--json", metavar="FILE", help="сохранить результат в JSON")
    ap.add_argument("--csv", metavar="FILE", help="сохранить результат в CSV")
    ap.add_argument("--topology-dot", metavar="FILE",
                    help="сохранить локальную топологию (этот ПК/шлюз/узлы) в Graphviz DOT")
    ap.add_argument("--snmp-topology", metavar="IP[,IP2,...]",
                    help="построить топологию через LLDP/MAC-таблицы управляемых "
                         "коммутаторов (SNMP), начиная с этих IP")
    ap.add_argument("--snmp-community", default="public",
                    help="SNMP community для --snmp-topology (по умолчанию public)")
    ap.add_argument("--snmp-dot", metavar="FILE", help="куда сохранить DOT для --snmp-topology")
    ap.add_argument("--passive-topology", type=float, metavar="СЕКУНД",
                    help="построить топологию, пассивно слушая LLDP/CDP-кадры от "
                         "коммутаторов (без SNMP); нужны права администратора/root и, "
                         "на Windows, Npcap")
    ap.add_argument("--iface", metavar="IFACE",
                    help="сетевой интерфейс для --passive-topology (по умолчанию — "
                         "выбор scapy по умолчанию)")
    ap.add_argument("--passive-dot", metavar="FILE", help="куда сохранить DOT для --passive-topology")
    ap.add_argument("--mdns", action="store_true",
                    help="дополнительно выполнить mDNS/Bonjour-поиск (порт 5353: принтеры "
                         "AirPrint, Chromecast, AirPlay/колонки и т.п.)")
    ap.add_argument("--risk", action="store_true",
                    help="оценить риск каждого узла (небезопасные протоколы, TLS, "
                         "веб-интерфейс без авторизации) и показать колонку риска")
    ap.add_argument("--risk-only", action="store_true",
                    help="как --risk, но в списке/экспорте остаются только узлы со "
                         "средним или высоким риском")
    ap.add_argument("--watch", type=float, metavar="МИНУТЫ",
                    help="режим наблюдения: пересканировать сеть каждые N минут и "
                         "печатать события журнала изменений (новый/пропавший узел, "
                         "смена MAC/портов); работает до Ctrl+C")
    ap.add_argument("--watch-log", default="netscan_history.json", metavar="FILE",
                    help="файл JSON с историей для --watch (по умолчанию "
                         "netscan_history.json в текущей папке)")
    args = ap.parse_args()

    networks = args.networks or [detect_local_network()]
    print("Подсети:", ", ".join(networks))

    if args.watch:
        watch_loop(networks, args)
        return

    hosts = scan(networks, args.timeout, args.workers)
    if not args.no_identify and hosts:
        identify_all(hosts, max(args.timeout, 1.0), args.workers)
    if args.mdns:
        n = mdns_merge(hosts)
        print(f"mDNS: найдено сервисов у {n} узлов.")
    if args.risk or args.risk_only:
        assess_all_risk(hosts)
    if args.risk_only:
        hosts = [h for h in hosts if h.get("risk", {}).get("level") in ("средний", "высокий")]

    if args.json:
        export(hosts, args.json)
    if args.csv:
        export(hosts, args.csv)

    if args.topology_dot:
        hosts_for_topo = [dict(h, ip=h["ip"]) for h in hosts]
        topo = topology.build_local_topology(
            hosts_for_topo, my_ip=netid.local_ip(), gateway_ip=netid.default_gateway())
        with open(args.topology_dot, "w", encoding="utf-8") as f:
            f.write(topology.export_dot(topo, "local-network"))
        print(f"Локальная топология сохранена в {args.topology_dot}\n"
              f"  Просмотр: dot -Tpng {args.topology_dot} -o topo.png  (пакет graphviz)\n"
              f"  или вставьте содержимое файла на https://dreampuf.github.io/GraphvizOnline/")

    if args.passive_topology:
        if not topology.SCAPY_AVAILABLE:
            print("Пассивная топология недоступна: scapy не установлен (pip install scapy).")
        elif not topology.has_sniff_privileges():
            print("Пассивная топология недоступна: нужны права администратора/root"
                  + (" и установленный Npcap (npcap.com)." if topology.IS_WIN else "."))
        else:
            print(f"Слушаю LLDP/CDP {args.passive_topology:.0f} сек на интерфейсе "
                  f"{args.iface or '(по умолчанию)'}...")
            passive_topo = topology.build_passive_topology(
                iface=args.iface, duration=args.passive_topology, hosts=hosts)
            print(f"Пассивная топология: {len(passive_topo['nodes'])} узлов, "
                  f"{len(passive_topo['edges'])} связей.")
            for err in passive_topo.get("errors", []):
                print("  ", err)
            if args.passive_dot:
                with open(args.passive_dot, "w", encoding="utf-8") as f:
                    f.write(topology.export_dot(passive_topo, "passive-lldp-cdp"))
                print(f"Сохранено в {args.passive_dot}")

    if args.snmp_topology:
        seeds = [s.strip() for s in args.snmp_topology.split(",") if s.strip()]
        print(f"Опрашиваю по SNMP: {', '.join(seeds)} (community={args.snmp_community})...")
        snmp_topo = topology.build_snmp_topology(
            seeds, community=args.snmp_community, hosts=hosts)
        print(f"SNMP-топология: {len(snmp_topo['nodes'])} узлов, {len(snmp_topo['edges'])} связей.")
        for err in snmp_topo.get("errors", []):
            print("  ", err)
        if args.snmp_dot:
            with open(args.snmp_dot, "w", encoding="utf-8") as f:
                f.write(topology.export_dot(snmp_topo, "switch-topology"))
            print(f"Сохранено в {args.snmp_dot}")
        else:
            print("  (используйте --snmp-dot FILE, чтобы сохранить DOT-файл)")

    show_risk = args.risk or args.risk_only
    while True:
        print_hosts(hosts, show_risk=show_risk)
        cmd = input("\nНомер узла для подключения, 'r' - пересканировать, 'q' - выход: ").strip()
        if cmd == "q":
            break
        if cmd == "r":
            hosts = scan(networks, args.timeout, args.workers)
            if not args.no_identify and hosts:
                identify_all(hosts, max(args.timeout, 1.0), args.workers)
            if args.mdns:
                mdns_merge(hosts)
            if show_risk:
                assess_all_risk(hosts)
            if args.risk_only:
                hosts = [h for h in hosts if h.get("risk", {}).get("level") in ("средний", "высокий")]
        elif cmd.isdigit() and 1 <= int(cmd) <= len(hosts):
            connect(hosts[int(cmd) - 1])


if __name__ == "__main__":
    main()
