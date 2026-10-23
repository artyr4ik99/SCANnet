"""
Universal Camera Viewer — просмотр и анализ нескольких IP-камер (RTSP / ONVIF)
ЛЮБОГО производителя: Tiandy, Hikvision, Dahua, Uniview, Reolink, Foscam,
Axis, Hanwha/Samsung, Bosch, Vivotek, Amcrest, TP-Link/Tapo и другие камеры
со стандартным RTSP- или ONVIF-доступом.

Возможности:
  * много камер, раскладки (авто, 1x1, 2x2, 3x3, 4x4, 1+5, 1+7), страницы, «тур»
  * двойной поток: лёгкий суб-поток в сетке, основной — при разворачивании
  * развернуть камеру (двойной клик), полноэкранный режим одной камеры
  * цифровой зум/панорамирование колесом мыши и перетаскиванием в фокусе
  * перетаскивание плиток мышью для смены порядка камер
  * улучшение изображения (яркость/контраст/резкость/шумодав) на лету
  * снимки, запись в MP4: всегда / только по движению / выключено
  * запись без перекодирования (ffmpeg -c copy) или покадрово через OpenCV
  * аппаратное декодирование (CUDA/DXVA2/D3D11VA/QSV) при наличии ffmpeg
  * звук RTSP-потока (через ffplay), включается на одной камере за раз
  * автоподбор подключения: проверка сети, RTSP, перебор путей разных
    производителей, ONVIF GetStreamUri
  * поиск камер в сети (скан подсети, включая большие сети 10.x.x.x/172.16.x.x,
    + ONVIF WS-Discovery) с перебором типовых заводских логинов/паролей и
    прямым добавлением найденных камер в просмотр — ТОЛЬКО для собственной
    или явно авторизованной для аудита сети (см. предупреждение в окне поиска)
  * анализ потоков (FPS, кодек, разрыв связи, аптайм) + экспорт CSV
  * детектор движения со снимками событий, цветной индикатор состояния
  * подробная диагностика с отчётом в файл
  * неоновый тёмный интерфейс
  * [netsuite] окно «Поиск камер» расширено до универсального сканера сети:
    определение производителя по MAC (OUI), догадка ОС по TTL, NetBIOS-имя,
    SNMP sysDescr, SSDP/UPnP-поиск, итоговый тип устройства (камера, роутер,
    NAS, принтер, ПК и т.д.) для ЛЮБОГО найденного узла, не только камер
  * [netsuite] подключение к любому найденному узлу прямо из сканера: SSH,
    Telnet, RDP, VNC, открытие веб-интерфейса в браузере, сетевая папка
    (SMB) или «сырой» TCP-клиент внутри приложения — не только добавление
    камеры в просмотр
  * [netsuite] экспорт результатов сканирования в CSV/JSON

Зависимости:  pip install opencv-python pillow numpy
Необязательно, но желательно:  ffmpeg + ffplay в PATH (или рядом с .exe) —
нужны для записи без перекодирования, аппаратного декодирования и звука.
"""

import os
import sys


def resource_path(*parts):
    """Путь к файлу ресурса (иконка и т.п.), который работает как при
    запуске из исходников, так и из собранного PyInstaller-экзешника
    (--onefile распаковывает данные во временную папку sys._MEIPASS)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


ICON_PATH = resource_path("assets", "netsuite.ico")

# RTSP по TCP (задаётся ДО импорта cv2); расширяется apply_ffmpeg_options()
os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS", "rtsp_transport;tcp")
os.environ.setdefault("OPENCV_LOG_LEVEL", "SILENT")

import base64
import collections
import csv
import hashlib
import http.client
import ipaddress
import json
import math
import queue
import re
import select
import shutil
import socket
import subprocess
import threading
import time
import uuid
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlsplit
from xml.sax.saxutils import escape as xml_escape

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import cv2
import numpy as np
from PIL import Image, ImageTk

import netid  # определение устройств: OUI/вендор, ОС по TTL, SNMP, SSDP, тип узла
import topology  # построение и экспорт топологии сети (локальная / через SNMP)
import risk  # пассивная оценка риска узла по открытым портам/баннерам/TLS

# Скрывать консольные окна ffmpeg/ffplay/ping, запущенных из-под Windows
if os.name == "nt":
    _NOWIN = subprocess.STARTUPINFO()
    _NOWIN.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    _POPEN_FLAGS = {"startupinfo": _NOWIN, "creationflags": subprocess.CREATE_NO_WINDOW}
else:
    _POPEN_FLAGS = {}

# ======================================================================
#  Пути и настройки
# ======================================================================
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)          # рядом с .exe
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(BASE_DIR, "cameras.json")
LOG_PATH = os.path.join(BASE_DIR, "viewer.log")
SNAP_DIR = os.path.join(BASE_DIR, "snapshots")
REC_DIR = os.path.join(BASE_DIR, "records")
EVENT_DIR = os.path.join(BASE_DIR, "events")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

SETTINGS_DEFAULT = {
    "netmask": "255.255.255.0",
    "gateway": "",
    "motion": True,
    "motion_threshold": 2.0,     # % изменившихся пикселей
    "save_events": True,         # сохранять снимок при движении
    "segment_min": 30,           # длина файла записи, минут
    "tour_sec": 10,              # смена страницы в режиме «Тур»
    "record_mode": "motion",     # always | motion | off — глобальный режим записи по умолчанию
    "motion_pre_sec": 5,         # буфер «до события», сек (только покадровая запись)
    "motion_post_sec": 10,       # сколько ещё писать после того, как движение закончилось
    "record_copy": True,         # писать без перекодирования через ffmpeg -c copy (если ffmpeg есть)
    "hwaccel": "none",           # none | cuda | dxva2 | d3d11va | qsv
    "ui_theme": "guard",         # guard | neon | classic
}

LAYOUTS = ["Авто", "1x1", "2x2", "3x3", "4x4", "1+5", "1+7"]

# Типовые пути RTSP-потоков у разных производителей IP-камер. Список собран так,
# чтобы одной и той же функцией перебора путей (find_paths / guess_credentials)
# можно было подобрать поток у Tiandy, Hikvision, Dahua, Uniview, Reolink,
# Foscam, Axis, Hanwha/Samsung, Bosch, Vivotek, Amcrest, TP-Link/Tapo,
# Grandstream и большинства камер с «типовым» ONVIF/RTSP-сервером.
CANDIDATE_PATHS = [
    # Tiandy / типовые «канал/поток»
    "/1/1", "/1/2", "/1/3", "/2/1", "/profile1", "/profile2",
    # Hikvision / HiLook / Annke / многие OEM на базе Hikvision
    "/Streaming/Channels/101", "/Streaming/Channels/102",
    "/Streaming/Channels/1", "/h264/ch1/main/av_stream", "/h264/ch1/sub/av_stream",
    # Dahua / Imou / Amcrest / Lorex (часто на базе Dahua)
    "/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1",
    # Uniview
    "/media/video1", "/media/video2",
    # Reolink
    "/h264Preview_01_main", "/h264Preview_01_sub",
    # Foscam
    "/videoMain", "/videoSub",
    # Axis
    "/axis-media/media.amp", "/axis-media/media.amp?videocodec=h264",
    # Hanwha/Samsung Wisenet
    "/profile2/media.smp", "/onvif/profile2/media.smp",
    # Bosch
    "/rtsp_tunnel", "/video1",
    # Vivotek
    "/live.sdp", "/live2.sdp",
    # TP-Link Tapo / Grandstream / Ubiquiti и общие варианты
    "/stream1", "/stream2", "/stream", "/live", "/live/ch0", "/live/main",
    "/ch01/0", "/ch01/1", "/11", "/12", "/video1", "/onvif1", "/onvif2",
    "/MediaInput/h264", "/mpeg4", "/h264", "/",
]

# Типовые суб-потоки (ниже разрешение/битрейт) — используются как 2-й канал
CANDIDATE_SUB_PATHS = [
    "/1/2", "/2/2", "/profile2", "/Streaming/Channels/102",
    "/cam/realmonitor?channel=1&subtype=1", "/media/video2",
    "/h264Preview_01_sub", "/videoSub", "/ch01/1", "/12", "/stream2",
]

SCAN_PORTS = (554, 8554, 10554, 80, 8080, 8000, 443, 88, 2020, 9000)
# «Быстрый» набор портов — используется для больших сетей (например целый
# блок 10.x.x.x/16), чтобы скан укладывался в разумное время.
SCAN_PORTS_FAST = (554, 80, 8080, 8000)

SCAN_MAX_HOSTS = 65536      # максимум адресов за один запуск скана (≈ сеть /16)
SCAN_CONFIRM_HOSTS = 1024   # начиная с этого размера сети — требуем явное подтверждение,
                             # что это своя/авторизованная для аудита сеть

HWACCEL_OPTIONS = {
    "none": "",
    "cuda": "hwaccel;cuda",
    "dxva2": "hwaccel;dxva2",
    "d3d11va": "hwaccel;d3d11va",
    "qsv": "hwaccel;qsv",
}

# Типовые логины/пароли «из коробки» у разных производителей IP-камер
# (Tiandy, Hikvision, Dahua, Uniview, Reolink, Foscam, Axis, Bosch и др.).
#
# ВАЖНО: это список только для аудита СВОЕГО оборудования — чтобы владелец
# сети мог быстро найти камеры, на которых ещё не сменили заводской пароль,
# и закрыть эту дыру. Используйте сканер и подбор паролей только в сетях,
# которыми вы владеете или на тестирование которых у вас есть письменное
# разрешение. Подключение к чужим камерам без разрешения владельца незаконно.
DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", ""), ("admin", "12345"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "888888"), ("admin", "password"),
    ("admin", "tiandy"), ("admin", "admin1"), ("admin", "1234"),
    ("admin", "12345678"), ("admin", "123456789"), ("admin", "admin12345"),
    ("admin", "meinsm"),            # Dahua «challenge» pass иногда ставят так
    ("888888", "888888"), ("666666", "666666"),
    ("root", "root"), ("root", "12345"), ("root", "pass"),
    ("user", "user"), ("guest", "guest"), ("supervisor", "supervisor"),
    ("ubnt", "ubnt"),               # Ubiquiti
    ("service", "service"),
]


_FFMPEG_CACHE = {}


def ffmpeg_path():
    """Путь к ffmpeg: сначала рядом с программой, потом в PATH. Результат кэшируется —
    чтобы не трогать диск на каждый кадр при проверке режима записи."""
    if "ffmpeg" not in _FFMPEG_CACHE:
        p = None
        for name in ("ffmpeg.exe", "ffmpeg"):
            local = os.path.join(BASE_DIR, name)
            if os.path.isfile(local):
                p = local
                break
        _FFMPEG_CACHE["ffmpeg"] = p or shutil.which("ffmpeg")
    return _FFMPEG_CACHE["ffmpeg"]


def ffplay_path():
    if "ffplay" not in _FFMPEG_CACHE:
        p = None
        for name in ("ffplay.exe", "ffplay"):
            local = os.path.join(BASE_DIR, name)
            if os.path.isfile(local):
                p = local
                break
        _FFMPEG_CACHE["ffplay"] = p or shutil.which("ffplay")
    return _FFMPEG_CACHE["ffplay"]


def apply_ffmpeg_options(settings):
    """Пересобирает OPENCV_FFMPEG_CAPTURE_OPTIONS: TCP-транспорт + hwaccel из настроек.
    Нужно вызывать до открытия потоков; на уже открытые камеры влияет после переподключения."""
    opts = ["rtsp_transport;tcp"]
    hw = HWACCEL_OPTIONS.get(settings.get("hwaccel", "none"), "")
    if hw:
        opts.append(hw)
    os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "|".join(opts)


def new_camera(**kw):
    cam = {"id": uuid.uuid4().hex[:6], "name": "Камера", "ip": "", "port": 554,
           "user": "admin", "password": "", "path": "/1/1", "path_sub": "", "enabled": True,
           "sound": False, "record_mode": "inherit",   # inherit | always | motion | off
           "enhance": {"auto": False, "brightness": 0, "contrast": 1.0,
                       "sharpen": False, "denoise": False}}
    enh = kw.pop("enhance", None)
    cam.update(kw)
    if enh:
        cam["enhance"].update(enh)
    return cam


def load_config():
    cfg = {"settings": dict(SETTINGS_DEFAULT), "cameras": [], "layout": "Авто"}
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        cfg["settings"].update(data.get("settings", {}))
        cfg["cameras"] = [new_camera(**c) for c in data.get("cameras", [])]
        cfg["layout"] = data.get("layout", cfg["layout"])
    except FileNotFoundError:
        pass
    except Exception:
        pass
    if not cfg["cameras"]:
        cfg["cameras"] = [new_camera(name="Камера 1", ip="")]
    return cfg


def save_config(cfg):
    try:
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CONFIG_PATH)
    except OSError:
        pass


def safe_name(cam):
    ascii_part = re.sub(r"[^A-Za-z0-9]+", "_", cam.get("name", "")).strip("_")
    return f"{cam['id']}_{ascii_part}" if ascii_part else cam["id"]


def build_url(cam, sub=False):
    user, pwd = cam.get("user", ""), cam.get("password", "")
    auth = f"{quote(user, safe='')}:{quote(pwd, safe='')}@" if user else ""
    path = (cam.get("path_sub") if sub else cam.get("path")) or cam.get("path") or "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"rtsp://{auth}{cam['ip']}:{cam['port']}{path}"


def effective_record_mode(cam, settings):
    m = cam.get("record_mode", "inherit")
    return settings.get("record_mode", "motion") if m == "inherit" else m


def save_jpg(path, frame):
    """cv2.imwrite не умеет юникодные пути в Windows — пишем через imencode."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ok, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 92])
    if ok:
        buf.tofile(path)
    return ok


def fmt_time(sec):
    sec = int(sec)
    return f"{sec // 3600:d}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


# ======================================================================
#  Сетевые функции (без GUI)
# ======================================================================
def tcp_open(ip, port, timeout=1.0):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def ping(ip, timeout_ms=1000):
    try:
        if os.name == "nt":
            cmd, flags = ["ping", "-n", "1", "-w", str(timeout_ms), ip], 0x08000000
        else:
            cmd, flags = ["ping", "-c", "1", "-W", "1", ip], 0
        r = subprocess.run(cmd, capture_output=True, timeout=6, creationflags=flags)
        return r.returncode == 0
    except Exception:
        return False


def local_ip_for(ip):
    """IP сетевой карты, через которую компьютер пойдёт к камере."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ip, 9))
        addr = s.getsockname()[0]
        s.close()
        return addr
    except OSError:
        return None


def local_ips():
    ips = set()
    try:
        for a in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not a.startswith("127."):
                ips.add(a)
    except OSError:
        pass
    return sorted(ips)


def local_interfaces():
    """Список (ip, netmask) локальных IPv4-интерфейсов этого компьютера (Ethernet,
    Wi-Fi, VPN и т.д.) — через `ipconfig` на Windows и `ip addr` на Linux/macOS.
    При любой ошибке парсинга падает обратно на local_ips() с маской /24."""
    out = []
    try:
        if os.name == "nt":
            r = subprocess.run(["ipconfig"], capture_output=True, text=True,
                               timeout=5, **_POPEN_FLAGS)
            ip = None
            for line in r.stdout.splitlines():
                line = line.strip()
                m = re.match(r"IPv4.*?:\s*([\d.]+)", line)
                if m:
                    ip = m.group(1)
                    continue
                m = re.match(r"(?:Subnet Mask|Маска подсети)[^:]*:\s*([\d.]+)", line, re.I)
                if m and ip:
                    out.append((ip, m.group(1)))
                    ip = None
        else:
            r = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True,
                               text=True, timeout=5)
            for line in r.stdout.splitlines():
                m = re.search(r"inet\s+([\d.]+)/(\d+)", line)
                if m:
                    mask = str(ipaddress.IPv4Network(f"0.0.0.0/{m.group(2)}").netmask)
                    out.append((m.group(1), mask))
    except Exception:
        pass
    return out or [(ip, "255.255.255.0") for ip in local_ips()]


def routed_10_networks():
    """CIDR сетей 10.x.x.x, до которых у компьютера есть МАРШРУТ (через шлюз —
    например через управляемый коммутатор/роутер с несколькими VLAN), даже
    если собственный IP компьютера не в сети 10.x.x.x (например, ПК в
    192.168.x.x, а камеры — в 10.x.x.x за тем же коммутатором). Читает
    системную таблицу маршрутизации: `route print` на Windows, `ip route`
    на Linux/macOS."""
    nets = set()
    try:
        if os.name == "nt":
            r = subprocess.run(["route", "print", "-4"], capture_output=True, text=True,
                               timeout=5, **_POPEN_FLAGS)
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"^10(\.\d{1,3}){3}$", parts[0]):
                    try:
                        nets.add(str(ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)))
                    except ValueError:
                        continue
        else:
            r = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                m = re.match(r"^10(\.\d{1,3}){3}/\d+", line)
                if m:
                    try:
                        nets.add(str(ipaddress.ip_network(m.group(0), strict=False)))
                    except ValueError:
                        continue
    except Exception:
        pass
    return nets


def my_10_networks():
    """CIDR сетей вида 10.x.x.x, которые ВИДНЫ этому компьютеру прямо сейчас —
    либо потому что на одном из его адаптеров уже есть адрес в такой сети,
    либо потому что в таблице маршрутизации есть путь к ней (через шлюз за
    коммутатором/роутером). Используется кнопкой «Мои сети 10.x.x.x», чтобы не
    требовать ручного ввода CIDR и не сканировать чужие/недоступные диапазоны
    этого огромного приватного блока."""
    nets = set()
    for ip, mask in local_interfaces():
        if not ip.startswith("10."):
            continue
        try:
            nets.add(str(ipaddress.ip_network(f"{ip}/{mask}", strict=False)))
        except ValueError:
            continue
    nets |= routed_10_networks()
    return sorted(nets, key=lambda n: tuple(int(p) for p in n.split("/")[0].split(".")))


def http_banner(ip, port):
    if not port:
        return ""
    try:
        c = http.client.HTTPConnection(ip, port, timeout=2)
        c.request("GET", "/")
        r = c.getresponse()
        server = r.getheader("Server") or ""
        body = r.read(4096).decode(errors="ignore")
        c.close()
        m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
        title = m.group(1).strip() if m else ""
        return " | ".join(x for x in (server, title) if x) or f"HTTP {r.status}"
    except Exception:
        return ""


def _md5(x):
    return hashlib.md5(x.encode()).hexdigest()


def _recv_rtsp(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    head, _, body = buf.partition(b"\r\n\r\n")
    m = re.search(rb"Content-Length:\s*(\d+)", head, re.I)
    if m:
        need = int(m.group(1))
        while len(body) < need:
            chunk = s.recv(4096)
            if not chunk:
                break
            body += chunk
    return head.decode(errors="ignore"), body.decode(errors="ignore")


def sdp_codec(body):
    m = re.search(r"m=video.*?a=rtpmap:\d+\s+([A-Za-z0-9\-]+)/", body, re.S)
    return m.group(1).upper() if m else ""


def rtsp_probe(ip, port, user, pwd, path, timeout=4):
    """RTSP DESCRIBE напрямую. Возвращает (код | None, строка статуса, видеокодек)."""
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    uri = f"rtsp://{ip}:{port}{path}"

    def req(auth=None, cseq=1):
        h = (f"DESCRIBE {uri} RTSP/1.0\r\nCSeq: {cseq}\r\n"
             "Accept: application/sdp\r\nUser-Agent: UniversalCamViewer\r\n")
        if auth:
            h += f"Authorization: {auth}\r\n"
        return (h + "\r\n").encode()

    def code_of(head):
        return int(head.split()[1]) if head.startswith("RTSP") else 0

    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
    except Exception as e:
        return None, f"порт {port} недоступен: {e}", ""
    try:
        s.settimeout(timeout)
        s.sendall(req())
        head, body = _recv_rtsp(s)
        code = code_of(head)
        if code == 401 and user:
            chal = re.findall(r"WWW-Authenticate:\s*(.*)", head, re.I)
            chal.sort(key=lambda x: 0 if x.lower().startswith("digest") else 1)
            if chal:
                kind, _, rest = chal[0].strip().partition(" ")
                if kind.lower() == "basic":
                    auth = "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()
                else:
                    p = dict(re.findall(r'(\w+)="?([^",]+)"?', rest))
                    ha1 = _md5(f"{user}:{p['realm']}:{pwd}")
                    ha2 = _md5(f"DESCRIBE:{uri}")
                    extra = ""
                    if "qop" in p:
                        nc, cn = "00000001", "0a4f113b"
                        resp = _md5(f"{ha1}:{p['nonce']}:{nc}:{cn}:auth:{ha2}")
                        extra = f', qop=auth, nc={nc}, cnonce="{cn}"'
                    else:
                        resp = _md5(f"{ha1}:{p['nonce']}:{ha2}")
                    auth = (f'Digest username="{user}", realm="{p["realm"]}", '
                            f'nonce="{p["nonce"]}", uri="{uri}", response="{resp}"{extra}')
                s.sendall(req(auth, 2))
                head, body = _recv_rtsp(s)
                code = code_of(head)
        return code, head.split("\r\n")[0], (sdp_codec(body) if code == 200 else "")
    except Exception as e:
        return None, f"ошибка RTSP: {e}", ""
    finally:
        s.close()


def find_paths(ip, port, user, pwd):
    """Перебирает типовые пути. Возвращает ([(путь, кодек)], [коды ответов])."""
    def one(p):
        code, _, codec = rtsp_probe(ip, port, user, pwd, p)
        return p, code, codec

    with ThreadPoolExecutor(4) as ex:
        res = list(ex.map(one, CANDIDATE_PATHS))
    return [(p, c) for p, code, c in res if code == 200], [code for _, code, _ in res]


def explain_rtsp(code, text, codec):
    if code is None:
        return f"✗ {text}. Проверьте IP, порт RTSP и включён ли RTSP на камере."
    if code == 200:
        extra = ""
        if codec in ("H265", "HEVC"):
            extra = " Кодек H.265: если видео не открывается — переключите камеру на H.264 или выберите доп. поток."
        return f"✓ RTSP работает ({text}), кодек: {codec or 'не определён'}.{extra}"
    if code == 401:
        return "✗ 401: логин или пароль не приняты."
    if code == 404:
        return "✗ 404: такого пути потока нет — нажмите «Подобрать путь» или «ONVIF»."
    return f"✗ Камера ответила: {text}"


# ---------------------------- ONVIF ----------------------------------
WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
PWD_DIGEST = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
B64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"


def _soap(body, user=None, pwd="", offset=0.0):
    header = ""
    if user:
        nonce = os.urandom(16)
        created = datetime.fromtimestamp(time.time() + offset, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        digest = base64.b64encode(hashlib.sha1(nonce + created.encode() + pwd.encode()).digest()).decode()
        header = (f'<wsse:Security xmlns:wsse="{WSSE}" xmlns:wsu="{WSU}"><wsse:UsernameToken>'
                  f"<wsse:Username>{xml_escape(user)}</wsse:Username>"
                  f'<wsse:Password Type="{PWD_DIGEST}">{digest}</wsse:Password>'
                  f'<wsse:Nonce EncodingType="{B64}">{base64.b64encode(nonce).decode()}</wsse:Nonce>'
                  f"<wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security>")
    return ('<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            f"<s:Header>{header}</s:Header><s:Body>{body}</s:Body></s:Envelope>")


def _http_post(ip, port, path, xml, timeout=4):
    c = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        c.request("POST", path, xml.encode(), {"Content-Type": "application/soap+xml; charset=utf-8"})
        r = c.getresponse()
        return r.status, r.read().decode(errors="ignore")
    finally:
        c.close()


def onvif_streams(ip, user, pwd, ports=(80, 8080, 8000, 8899, 2020)):
    """Спрашивает у камеры точные RTSP-адреса. Возвращает (список потоков, текст ошибки)."""
    last_err = "ONVIF не отвечает (порты %s закрыты)" % ", ".join(map(str, ports))
    for port in ports:
        if not tcp_open(ip, port, 1.0):
            continue
        try:
            offset = 0.0
            st, txt = _http_post(ip, port, "/onvif/device_service", _soap(
                '<GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>'))
            m = re.search(r"UTCDateTime.*?Hour>\s*(\d+)<.*?Minute>\s*(\d+)<.*?Second>\s*(\d+)<"
                          r".*?Year>\s*(\d+)<.*?Month>\s*(\d+)<.*?Day>\s*(\d+)<", txt, re.S)
            if m:
                h, mi, s, y, mo, d = map(int, m.groups())
                offset = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp() - time.time()

            st, txt = _http_post(ip, port, "/onvif/device_service", _soap(
                '<GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl">'
                "<Category>Media</Category></GetCapabilities>", user, pwd, offset))
            if st == 401 or "NotAuthorized" in txt:
                return [], "ONVIF: логин или пароль не приняты"
            media_port, media_path = port, "/onvif/media_service"
            m = re.search(r"Media>\s*<[^>]*XAddr>\s*([^<\s]+)", txt)
            if m:
                u = urlsplit(m.group(1).replace("&amp;", "&"))
                media_path = u.path or media_path
                media_port = u.port or 80

            st, txt = _http_post(ip, media_port, media_path, _soap(
                '<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>', user, pwd, offset))
            if st == 401 or "NotAuthorized" in txt:
                return [], "ONVIF: логин или пароль не приняты"
            profiles = re.findall(r'<(?:\w+:)?Profiles\b[^>]*?token="([^"]+)"[^>]*>(.*?)</(?:\w+:)?Profiles>',
                                  txt, re.S)
            out = []
            for token, body in profiles:
                name = (re.search(r"<(?:\w+:)?Name>([^<]*)<", body) or [None, token])[1]
                enc = (re.search(r"Encoding>([^<]+)<", body) or [None, ""])[1]
                res = re.search(r"Width>(\d+)<.*?Height>(\d+)<", body, re.S)
                st2, t2 = _http_post(ip, media_port, media_path, _soap(
                    '<GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl"><StreamSetup>'
                    '<Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream>'
                    '<Transport xmlns="http://www.onvif.org/ver10/schema"><Protocol>RTSP</Protocol></Transport>'
                    f"</StreamSetup><ProfileToken>{xml_escape(token)}</ProfileToken></GetStreamUri>",
                    user, pwd, offset))
                mu = re.search(r"Uri>\s*([^<\s]+)<", t2)
                if not mu:
                    continue
                uri = mu.group(1).replace("&amp;", "&")
                u = urlsplit(uri)
                path = (u.path or "/") + (("?" + u.query) if u.query else "")
                out.append({"name": name, "token": token, "uri": uri, "path": path,
                            "port": u.port or 554, "enc": enc,
                            "res": f"{res.group(1)}x{res.group(2)}" if res else ""})
            if out:
                return out, ""
            last_err = f"ONVIF (порт {port}): профили потоков не найдены"
        except Exception as e:
            last_err = f"ONVIF (порт {port}): {e}"
    return [], last_err


def ws_discovery(timeout=2.5):
    """ONVIF WS-Discovery: камеры сами откликаются на мультикаст-запрос."""
    probe = ('<?xml version="1.0" encoding="UTF-8"?>'
             '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
             'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
             'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
             'xmlns:dn="http://www.onvif.org/ver10/network/wsdl"><e:Header>'
             f"<w:MessageID>uuid:{uuid.uuid4()}</w:MessageID>"
             '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
             '<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
             "</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>")
    socks = []
    for ip in (local_ips() or [""]):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            if ip:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
            s.bind((ip, 0))
            s.sendto(probe.encode(), ("239.255.255.250", 3702))
            socks.append(s)
        except OSError:
            continue
    found = {}
    end = time.time() + timeout
    while socks and time.time() < end:
        ready, _, _ = select.select(socks, [], [], 0.3)
        for s in ready:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            txt = data.decode(errors="ignore")
            name = hw = ""
            m = re.search(r"Scopes>([^<]+)<", txt)
            if m:
                for sc in m.group(1).split():
                    if "/name/" in sc:
                        name = unquote(sc.split("/name/")[-1])
                    elif "/hardware/" in sc:
                        hw = unquote(sc.split("/hardware/")[-1])
            found[addr[0]] = {"name": name, "hw": hw}
    for s in socks:
        s.close()
    return found


def guess_credentials(ip, rtsp_port, onvif_user=None, quick_paths=("/1/1", "/", "/Streaming/Channels/101")):
    """Подбирает типовые заводские логин/пароль — сначала по RTSP, затем по ONVIF —
    и работает одинаково для любого производителя камеры (Tiandy, Hikvision, Dahua,
    Uniview, Reolink, Foscam, Axis и т.д.), а не только для камер с «тиандиевскими»
    путями потоков.

    Алгоритм для RTSP в два шага, чтобы не перебирать все пути под каждую пару
    логин/пароль (это было бы слишком медленно для целой подсети):
      1) быстрая проверка пары логин/пароль на нескольких частых путях — RTSP
         отвечает 401, если данные неверны, ЕЩЁ ДО проверки существования пути,
         так что это быстро отсеивает неверные пары;
      2) как только находится пара, на которую камера НЕ ответила 401 (то есть
         логин/пароль приняты), запускается полный перебор CANDIDATE_PATHS уже
         только для этой пары — чтобы найти настоящий путь потока этого
         конкретного производителя.

    Останавливается, как только порт вообще недоступен (нет смысла перебирать
    дальше). Возвращает dict {user, password, path, port, via} или None.
    Предназначено только для проверки собственного/авторизованного оборудования."""
    if rtsp_port and tcp_open(ip, rtsp_port, 1.0):
        for user, pwd in DEFAULT_CREDENTIALS:
            reachable = False
            accepted = False
            for path in quick_paths:
                code, _, _ = rtsp_probe(ip, rtsp_port, user, pwd, path, timeout=1.5)
                if code is None:
                    break
                reachable = True
                if code == 200:
                    return {"user": user, "password": pwd, "path": path,
                            "port": rtsp_port, "via": "RTSP"}
                if code != 401:
                    # путь не тот, но логин/пароль, похоже, приняты (401 означал бы отказ
                    # в авторизации) — стоит перебрать все типовые пути именно с этой парой
                    accepted = True
            if not reachable:
                break
            if accepted:
                found, _ = find_paths(ip, rtsp_port, user, pwd)
                if found:
                    return {"user": user, "password": pwd, "path": found[0][0],
                            "port": rtsp_port, "via": "RTSP"}
    for onvif_port in (80, 8080, 8000, 8899, 2020, 88, 9000):
        if not tcp_open(ip, onvif_port, 0.8):
            continue
        for user, pwd in DEFAULT_CREDENTIALS:
            try:
                streams, err = onvif_streams(ip, user, pwd, ports=(onvif_port,))
            except Exception:
                continue
            if streams:
                return {"user": user, "password": pwd, "path": streams[0]["path"],
                        "port": streams[0]["port"], "via": "ONVIF"}
            if "логин" in err:
                continue  # неверные данные — пробуем следующую пару
        break  # порт отвечал, но ни одна пара не подошла — дальше не пробуем
    return None


def parse_subnet_input(text):
    """Гибкий разбор подсети для поля ввода: принимает не только строгий CIDR
    (10.188.157.0/24), но и короткие формы вида «10.188.157», «192.168.1.x»,
    «192.168.1.*», «10.188.157.1-254» (диапазон игнорируется, берётся /24).
    Если октетов меньше четырёх или указан хвост-маска (x/*/0), размер сети
    подбирается по числу явно заданных октетов. Бросает ValueError, если
    строку совсем не удалось разобрать."""
    s = text.strip()
    if not s:
        raise ValueError("пустая строка")
    if "/" in s:
        return ipaddress.ip_network(s, strict=False)
    s = re.sub(r"[-–].*$", "", s)          # отбросить диапазон после дефиса
    parts = [p for p in s.split(".")]
    while parts and parts[-1].strip().lower() in ("x", "xxx", "*", "", "0"):
        parts.pop()
    if not parts:
        raise ValueError("не удалось распознать адрес")
    n = len(parts)
    prefix = {1: 8, 2: 16, 3: 24, 4: 24}.get(n, 24)   # полный адрес без '/' тоже трактуем как /24
    while len(parts) < 4:
        parts.append("0")
    ip_str = ".".join(parts)
    return ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False)


def scan_subnet(cidr, progress=None, ports=None, timeout=None, workers=None):
    """Скан подсети TCP-коннектом по заданным портам, с баннером HTTP у найденных
    устройств. Параметры подбираются автоматически по размеру сети, чтобы один
    и тот же вызов одинаково годился и для домашней /24, и для целого блока
    10.x.x.x/16 (до SCAN_MAX_HOSTS адресов): для маленьких сетей — полный набор
    портов и щедрый таймаут, для больших — укороченный набор портов, меньший
    таймаут и больше потоков, а сами проверки (IP, порт) ставятся в один общий
    пул вместо последовательного перебора портов на каждый адрес."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    n = len(hosts)
    if ports is None:
        ports = SCAN_PORTS if n <= 4096 else SCAN_PORTS_FAST
    if timeout is None:
        timeout = 0.7 if n <= 4096 else 0.35
    if workers is None:
        workers = 48 if n <= 1024 else (128 if n <= 4096 else 256)

    tasks = [(ip, p) for ip in hosts for p in ports]
    if progress is not None:
        progress["total"], progress["done"] = len(tasks), 0

    open_ports = collections.defaultdict(list)

    def one(t):
        ip, p = t
        ok = tcp_open(ip, p, timeout)
        if progress is not None:
            progress["done"] += 1
        return ip, p, ok

    with ThreadPoolExecutor(workers) as ex:
        for ip, p, ok in ex.map(one, tasks):
            if ok:
                open_ports[ip].append(p)

    result = {ip: {"ports": sorted(op), "info": ""} for ip, op in open_ports.items()}

    # HTTP-баннер (производитель/модель из заголовка или <title>) — отдельным
    # пулом, только для адресов, где реально открыт веб-порт.
    def banner(ip):
        op = open_ports[ip]
        web = 80 if 80 in op else (8080 if 8080 in op else (8000 if 8000 in op else None))
        return ip, http_banner(ip, web) if web else ""

    web_ips = [ip for ip in result if any(p in open_ports[ip] for p in (80, 8080, 8000))]
    if web_ips:
        with ThreadPoolExecutor(min(32, len(web_ips))) as ex:
            for ip, info in ex.map(banner, web_ips):
                result[ip]["info"] = info
    return result


def diagnose_camera(cam, settings):
    """Полная проверка цепочки: сеть → порты → RTSP → пути → ONVIF. Возвращает текст отчёта."""
    ip = cam["ip"].strip()
    port = int(cam.get("port") or 554)
    user, pwd, path = cam.get("user", ""), cam.get("password", ""), cam.get("path") or "/"
    L, verdict = [], []
    add = L.append
    add(f"=== {cam['name']} · {ip}:{port}{path} · {datetime.now():%Y-%m-%d %H:%M:%S} ===")

    local = local_ip_for(ip)
    add(f"IP этого компьютера (интерфейс к камере): {local or 'не определён — нет маршрута'}")
    try:
        net = ipaddress.ip_network(f"{ip}/{settings.get('netmask') or '255.255.255.255'}", strict=False)
        add(f"Подсеть камеры: {net}  (рабочие адреса {net.network_address + 1} – {net.broadcast_address - 1})")
        if local:
            if ipaddress.ip_address(local) in net:
                add("  ✓ компьютер в одной подсети с камерой")
                if local == ip:
                    add("  ✗ адрес компьютера совпадает с адресом камеры (конфликт IP)")
                    verdict.append("Конфликт IP: компьютеру нужен другой адрес.")
            else:
                add(f"  ✗ компьютер НЕ в подсети камеры. Задайте сетевой карте адрес из диапазона выше "
                    f"(маска {settings.get('netmask')}) или настройте маршрут.")
                verdict.append("Сетевая карта компьютера не в подсети камеры.")
        gw = settings.get("gateway", "").strip()
        if gw:
            try:
                if ipaddress.ip_address(gw) not in net:
                    add(f"  ! шлюз {gw} вне подсети камеры")
            except ValueError:
                pass
    except ValueError:
        add("Подсеть: маска в настройках не распознана")

    add("Ping: " + ("ответ есть ✓" if ping(ip) else
                    "нет ответа (ICMP может быть закрыт — это не всегда ошибка)"))
    ports = tuple(dict.fromkeys((port, 554, 8554, 10554, 80, 8080, 8000, 443)))
    with ThreadPoolExecutor(len(ports)) as ex:
        res = list(ex.map(lambda p: tcp_open(ip, p, 1.5), ports))
    opened = [p for p, o in zip(ports, res) if o]
    add("Открытые TCP-порты: " + (", ".join(map(str, opened)) if opened else "ни одного из проверенных"))
    if not opened:
        verdict.append("Камера не отвечает по TCP: проверьте кабель, питание, IP, VLAN, брандмауэр.")

    code, text, codec = rtsp_probe(ip, port, user, pwd, path)
    add(f"RTSP {path}: {text}" + (f" · видеокодек {codec}" if codec else ""))
    ok_path = None
    if code == 200:
        ok_path = path
        verdict.append("RTSP работает: адрес, логин, пароль и путь верны.")
        if codec in ("H265", "HEVC"):
            verdict.append("Кодек H.265: если видео не открывается или тормозит — переключите на H.264 или возьмите доп. поток.")
    elif code is None:
        alt = [p for p in (554, 8554, 10554) if p != port and p in opened]
        if alt:
            add(f"  RTSP, вероятно, на порту {alt[0]}")
            verdict.append(f"Укажите RTSP-порт {alt[0]} в настройках камеры.")
        else:
            verdict.append("RTSP-порт закрыт: включите RTSP в веб-интерфейсе камеры или уточните порт.")
    else:
        found, codes = find_paths(ip, port, user, pwd)
        if found:
            add("Рабочие пути потока: " + ", ".join(f"{p} ({c or '?'})" for p, c in found))
            ok_path = found[0][0]
            verdict.append(f"Укажите путь {found[0][0]} (подошёл из перебора).")
        elif codes and all(c == 401 for c in codes if c):
            verdict.append("Все пути отвечают 401: логин или пароль неверны.")
        else:
            add("Перебор типовых путей не дал результата.")

    streams, err = onvif_streams(ip, user, pwd)
    if streams:
        add("ONVIF-профили:")
        for s in streams:
            add(f"  {s['name']}: {s['res'] or '?'} {s['enc']} → порт {s['port']}, путь {s['path']}")
        if not ok_path:
            verdict.append(f"По данным ONVIF используйте путь {streams[0]['path']} (порт {streams[0]['port']}).")
    else:
        add(f"ONVIF: {err}")

    add("")
    add("ИТОГ:")
    for v in (verdict or ["Причину автоматически определить не удалось — отправьте этот отчёт специалисту."]):
        add(f"  • {v}")
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
        fp = os.path.join(REPORT_DIR, f"diag_{safe_name(cam)}_{datetime.now():%Y%m%d_%H%M%S}.txt")
        with open(fp, "w", encoding="utf-8") as f:
            f.write("\n".join(L))
        add(f"Отчёт сохранён: {fp}")
    except OSError:
        pass
    return "\n".join(L)


# ======================================================================
#  Поток чтения камеры
# ======================================================================
def open_capture(url):
    props = []
    if hasattr(cv2, "CAP_PROP_OPEN_TIMEOUT_MSEC"):
        props = [cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 6000, cv2.CAP_PROP_READ_TIMEOUT_MSEC, 8000]
    try:
        if props:
            return cv2.VideoCapture(url, cv2.CAP_FFMPEG, props)
    except TypeError:
        pass
    return cv2.VideoCapture(url, cv2.CAP_FFMPEG)


class CameraWorker(threading.Thread):
    def __init__(self, cam, settings, log, report_path_found=None):
        super().__init__(daemon=True)
        self.cam = dict(cam)
        self.settings = settings
        self.log = log
        self.running = True
        self.lock = threading.Lock()
        self.full = None          # последний кадр в полном размере
        self.disp = None          # уменьшенный кадр для показа
        self.frame_id = 0
        self.target_w = 640
        self.state = "connecting"  # online | connecting | offline
        self.status = "Подключение…"
        self.last_error = ""
        self.fps = 0.0
        self.size = (0, 0)
        self.codec = ""
        self.frames = 0
        self.reconnects = 0
        self.connected_at = 0.0
        self.last_frame_at = 0.0
        self.motion = 0.0
        self.motion_active = False
        self.events = 0
        self.last_event_at = 0.0
        # --- запись
        self.manual_record = False      # пользователь нажал «Запись»
        self.record = False             # фактически пишем прямо сейчас (для индикатора)
        self.record_kind = ""           # "copy" (ffmpeg -c copy) | "reencode" (cv2) | ""
        self.rec_path = ""
        self._motion_rec_until = 0.0
        self._prev_gray = None
        self._writer = None
        self._writer_t0 = 0.0
        self._writer_size = None
        self._copy_proc = None
        self._prebuf = collections.deque()   # [(frame, t)] для пред-буфера при записи по движению
        # --- двойной поток
        self.has_sub = bool(cam.get("path_sub"))
        self.focused = False
        self.use_sub = self.has_sub
        self._switch_stream = False
        # --- автоподбор рабочего пути и устойчивость к нестабильной сети
        self.report_path_found = report_path_found  # cb(cam_id, is_sub, path) -> персист в конфиг
        self._autofind_done = False
        self._fail_times = collections.deque(maxlen=20)   # моменты обрывов основного потока
        self.auto_degraded = False     # True = временно ушли на суб-поток из-за нестабильности
        self._last_main_retry = 0.0
        # --- звук
        self.sound_proc = None
        self.sound_on = False

    # ---- служебное
    def stop(self):
        self.running = False
        self._stop_sound()
        self._stop_copy_proc()

    def set_focused(self, focused):
        """Переключает поток: в сетке — лёгкий суб-поток, в фокусе — основной.
        Если сейчас действует временный переход на суб-поток из-за нестабильной
        сети (auto_degraded), не дёргаем обратно на основной — им займётся
        периодическая попытка возврата внутри run()."""
        want_sub = self.has_sub and (not focused or self.auto_degraded)
        self.focused = focused
        if want_sub != self.use_sub:
            self.use_sub = want_sub
            self._switch_stream = True

    def _sleep(self, sec):
        end = time.time() + sec
        while self.running and time.time() < end and not self._switch_stream:
            time.sleep(0.1)

    def _set(self, state, status, log=True):
        if log and status != self.status:
            self.log(f"[{self.cam['name']}] {status}")
        self.state, self.status = state, status

    def _fail(self, err, backoff):
        if err != self.last_error:
            self.log(f"[{self.cam['name']}] {err}")
        self.last_error = err
        self._set("offline", err, log=False)
        self._sleep(backoff)

    # ---- устойчивость к нестабильной сети: учёт обрывов ОСНОВНОГО потока
    def _record_main_failure(self):
        """Вызывается при любом обрыве/неудаче именно основного потока.
        Если это была пробная попытка вернуться на основной после деградации —
        сразу откатываемся обратно на суб-поток, следующая попытка — через
        _MAIN_RETRY_SEC."""
        if self.use_sub or not self.has_sub:
            return
        now = time.time()
        self._fail_times.append(now)
        if self.auto_degraded:
            self.use_sub = True
            self._last_main_retry = now
            self.log(f"[{self.cam['name']}] основной поток всё ещё нестабилен — возвращаюсь на суб-поток")

    def _record_main_recovered(self):
        """Основной поток продержался достаточно долго — считаем его снова стабильным."""
        if self.use_sub or not self.has_sub:
            return
        if self.auto_degraded:
            self.auto_degraded = False
            self._fail_times.clear()
            self.log(f"[{self.cam['name']}] основной поток снова стабилен")

    _MAIN_RETRY_SEC = 90        # как часто пробовать вернуться на основной поток
    _MAIN_FAIL_WINDOW = 120     # окно, в котором считаем обрывы «частыми»
    _MAIN_FAIL_THRESHOLD = 3    # столько обрывов за окно -> уходим на суб-поток
    _MAIN_STABLE_SEC = 15       # столько сек. без обрыва -> поток снова «стабилен»

    def _maybe_adjust_stream(self):
        """Решает, не пора ли временно перейти на суб-поток (частые обрывы
        основного) или наоборот — попробовать вернуться на основной."""
        if not self.has_sub:
            return
        now = time.time()
        if self.focused and not self.use_sub and not self.auto_degraded:
            recent = [t for t in self._fail_times if now - t < self._MAIN_FAIL_WINDOW]
            if len(recent) >= self._MAIN_FAIL_THRESHOLD:
                self.use_sub = True
                self.auto_degraded = True
                self._last_main_retry = now
                self.log(f"[{self.cam['name']}] частые обрывы основного потока — "
                         f"временно перешёл на суб-поток")
        elif self.auto_degraded and self.use_sub and \
                now - self._last_main_retry > self._MAIN_RETRY_SEC:
            self.use_sub = False
            self._last_main_retry = now
            self.log(f"[{self.cam['name']}] пробую вернуться на основной поток…")

    # ---- звук (ffplay, без перекодирования видео — только аудиодорожка)
    def set_sound(self, on):
        if on == self.sound_on:
            return
        self.sound_on = on
        if on:
            self._start_sound()
        else:
            self._stop_sound()

    def _start_sound(self):
        self._stop_sound()
        exe = ffplay_path()
        if not exe:
            self.sound_on = False
            self.log(f"[{self.cam['name']}] звук недоступен: ffplay не найден (положите ffplay.exe рядом с программой)")
            return
        url = build_url(self.cam, sub=False)
        try:
            self.sound_proc = subprocess.Popen(
                [exe, "-rtsp_transport", "tcp", "-i", url, "-vn", "-nodisp",
                 "-autoexit", "-loglevel", "quiet"],
                **_POPEN_FLAGS)
        except Exception as e:
            self.sound_on = False
            self.log(f"[{self.cam['name']}] не удалось запустить звук: {e}")

    def _stop_sound(self):
        if self.sound_proc is not None:
            try:
                self.sound_proc.terminate()
            except Exception:
                pass
            self.sound_proc = None

    # ---- основной цикл
    def _try_autofind_path(self, c):
        """Авто-подбор рабочего RTSP-пути: перебирает типовые шаблоны
        производителей (CANDIDATE_PATHS/CANDIDATE_SUB_PATHS, см. начало
        файла) и, если находит отвечающий поток, сохраняет его — и в
        текущий self.cam, и (через report_path_found) в конфигурацию
        камеры, чтобы при следующем запуске подбор не повторялся.
        Возвращает True, если путь найден и применён."""
        self._autofind_done = True
        self._set("connecting", "Путь не отвечает — подбираю рабочий поток автоматически…")
        found, _ = find_paths(c["ip"], c["port"], c["user"], c["password"])
        if not found:
            return False
        new_path = found[0][0]
        key = "path_sub" if self.use_sub else "path"
        c[key] = new_path
        self.log(f"[{c['name']}] автоподбор нашёл рабочий {'суб-' if self.use_sub else ''}поток: {new_path}")
        if self.report_path_found:
            try:
                self.report_path_found(c["id"], self.use_sub, new_path)
            except Exception:
                pass
        return True

    def run(self):
        c = self.cam
        backoff = 3
        try:
            while self.running:
                self._maybe_adjust_stream()
                self._switch_stream = False
                self._set("connecting", "Подключение…", log=False)
                path = c.get("path_sub") or c["path"] if self.use_sub else c["path"]
                code, text, codec = rtsp_probe(c["ip"], c["port"], c["user"], c["password"], path)
                if codec:
                    self.codec = codec
                if code is None:
                    self._record_main_failure()
                    self._fail(text[0].upper() + text[1:], backoff)
                    backoff = min(backoff * 2, 30)
                    continue
                if code == 401:
                    self._record_main_failure()
                    self._fail("401: неверный логин или пароль", backoff)
                    backoff = min(backoff * 2, 30)
                    continue
                if code == 404:
                    if not self._autofind_done and self._try_autofind_path(c):
                        continue  # сразу пробуем найденный путь, без роста backoff
                    self._record_main_failure()
                    self._fail("404: неверный путь потока"
                               + (" (автоподбор не нашёл альтернативы)" if self._autofind_done else ""),
                               backoff)
                    backoff = min(backoff * 2, 30)
                    continue

                cap = open_capture(build_url(c, sub=self.use_sub))
                if not cap.isOpened():
                    cap.release()
                    self._record_main_failure()
                    self._fail("RTSP отвечает, но видео не открылось (кодек H.265? попробуйте H.264 / доп. поток)",
                               backoff)
                    backoff = min(backoff * 2, 30)
                    continue

                backoff = 3
                self._autofind_done = False
                self.last_error = ""
                self.connected_at = time.time()
                self._set("online", "Онлайн" + ("  (суб-поток)" if self.use_sub else ""))
                self._read_loop(cap)
                cap.release()
                self._close_writer()
                self._stop_copy_proc()
                with self.lock:
                    self.disp = None
                    self.full = None
                self.fps = 0.0
                if time.time() - self.connected_at >= self._MAIN_STABLE_SEC:
                    self._record_main_recovered()
                else:
                    self._record_main_failure()
                if self.running and not self._switch_stream:
                    self.reconnects += 1
                    self._set("connecting", "Поток прерван, переподключение…")
                    self._sleep(2)
        finally:
            self._close_writer()
            self._stop_copy_proc()
            self._stop_sound()

    _READ_FAIL_TOLERANCE = 3   # столько подряд неудачных cap.read() терпим перед разрывом —
                               # сглаживает кратковременные «заикания» нестабильной сети

    def _read_loop(self, cap):
        n, t0, last_motion, first = 0, time.time(), 0.0, True
        fail_streak = 0
        while self.running and not self._switch_stream:
            ok, frame = cap.read()
            if not ok or frame is None:
                fail_streak += 1
                if fail_streak >= self._READ_FAIL_TOLERANCE:
                    return
                time.sleep(0.15)
                continue
            fail_streak = 0
            now = time.time()
            h, w = frame.shape[:2]
            self.size = (w, h)
            self.frames += 1
            self.last_frame_at = now
            n += 1
            if first:
                first = False
                self.log(f"[{self.cam['name']}] видео получено: {w}x{h}"
                         + (f", {self.codec}" if self.codec else ""))
            if self.settings.get("motion", True) and now - last_motion >= 0.2:
                last_motion = now
                self._motion(frame, now)
            self._update_recording(frame, w, h, now)
            tw = self.target_w
            disp = frame if w <= tw else cv2.resize(frame, (tw, max(1, int(h * tw / w))),
                                                    interpolation=cv2.INTER_AREA)
            with self.lock:
                self.full, self.disp = frame, disp
                self.frame_id += 1
            if now - t0 >= 1.0:
                self.fps = n / (now - t0)
                n, t0 = 0, now

    # ---- движение
    def _motion(self, frame, now):
        small = cv2.resize(frame, (160, 90), interpolation=cv2.INTER_AREA)
        gray = cv2.GaussianBlur(cv2.cvtColor(small, cv2.COLOR_BGR2GRAY), (5, 5), 0)
        if self._prev_gray is not None:
            diff = cv2.absdiff(gray, self._prev_gray)
            self.motion = float(np.count_nonzero(diff > 25)) * 100.0 / diff.size
            self.motion_active = self.motion >= float(self.settings.get("motion_threshold", 2.0))
            if self.motion_active:
                self._motion_rec_until = now + float(self.settings.get("motion_post_sec", 10))
            if self.motion_active and now - self.last_event_at > 15:
                self.last_event_at = now
                self.events += 1
                self.log(f"[{self.cam['name']}] движение {self.motion:.1f}%")
                if self.settings.get("save_events", True):
                    path = os.path.join(EVENT_DIR, safe_name(self.cam), f"{datetime.now():%Y%m%d_%H%M%S}.jpg")
                    try:
                        save_jpg(path, frame)
                    except OSError:
                        pass
        self._prev_gray = gray

    # ---- решение «писать / не писать» на основе режима записи + движения
    def _want_record(self, now):
        mode = effective_record_mode(self.cam, self.settings)
        if mode == "always":
            auto = True
        elif mode == "motion":
            auto = now < self._motion_rec_until
        else:
            auto = False
        return auto or self.manual_record, mode

    def _update_recording(self, frame, w, h, now):
        want, mode = self._want_record(now)
        use_copy = bool(self.settings.get("record_copy", True)) and ffmpeg_path() is not None
        # буфер «до события» — нужен только для покадровой (re-encode) записи
        if not use_copy and mode == "motion" and not want:
            pre = float(self.settings.get("motion_pre_sec", 5))
            self._prebuf.append((frame.copy(), now))
            while self._prebuf and now - self._prebuf[0][1] > pre:
                self._prebuf.popleft()
        if want and not self.record:
            self._start_recording(use_copy)
        elif not want and self.record:
            self._stop_recording()
        if self.record:
            if self.record_kind == "reencode":
                self._write(frame, w, h)
            # при record_kind == "copy" пишет сам ffmpeg — кадры из Python не нужны

    def _start_recording(self, use_copy):
        if use_copy:
            if self._start_copy_proc():
                self.record, self.record_kind = True, "copy"
                return
            use_copy = False  # ffmpeg не взлетел — используем запасной вариант
        # покадровая запись: сперва сбрасываем пред-буфер (кадры до события)
        self.record, self.record_kind = True, "reencode"
        while self._prebuf:
            f, _ = self._prebuf.popleft()
            h, w = f.shape[:2]
            self._write(f, w, h)

    def _stop_recording(self):
        self.record, self.record_kind = False, ""
        self._close_writer()
        self._stop_copy_proc()
        self._prebuf.clear()

    # ---- запись без перекодирования (ffmpeg -c copy, сегментами)
    def _start_copy_proc(self):
        exe = ffmpeg_path()
        if not exe:
            return False
        d = os.path.join(REC_DIR, safe_name(self.cam))
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
        seg = max(60, int(float(self.settings.get("segment_min", 30)) * 60))
        url = build_url(self.cam, sub=False)
        pattern = os.path.join(d, "%Y%m%d_%H%M%S.mp4")
        cmd = [exe, "-y", "-rtsp_transport", "tcp", "-i", url, "-c", "copy",
               "-f", "segment", "-segment_time", str(seg), "-reset_timestamps", "1",
               "-strftime", "1", pattern]
        try:
            self._copy_proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, **_POPEN_FLAGS)
            self.rec_path = d
            self.log(f"[{self.cam['name']}] запись без перекодирования: {d}")
            return True
        except Exception as e:
            self.log(f"[{self.cam['name']}] ffmpeg не запустился ({e}), пишу покадрово")
            self._copy_proc = None
            return False

    def _stop_copy_proc(self):
        if self._copy_proc is not None:
            try:
                self._copy_proc.terminate()
                self._copy_proc.wait(timeout=3)
            except Exception:
                try:
                    self._copy_proc.kill()
                except Exception:
                    pass
            self._copy_proc = None

    # ---- запись покадрово (fallback, если нет ffmpeg)
    def _write(self, frame, w, h):
        if self.fps <= 0:
            return                      # ждём, пока измерится FPS
        seg = float(self.settings.get("segment_min", 30)) * 60
        if self._writer is not None and (time.time() - self._writer_t0 > seg or self._writer_size != (w, h)):
            self._close_writer()
        if self._writer is None:
            d = os.path.join(REC_DIR, safe_name(self.cam))
            try:
                os.makedirs(d, exist_ok=True)
            except OSError:
                pass
            path = os.path.join(d, f"{datetime.now():%Y%m%d_%H%M%S}.mp4")
            fps = self.fps if 3 <= self.fps <= 60 else 15.0
            wr = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*"mp4v"), fps, (w, h))
            if not wr.isOpened():
                self.manual_record = False
                self.log(f"[{self.cam['name']}] не удалось начать запись (папка программы должна быть без кириллицы)")
                return
            self._writer, self._writer_t0, self._writer_size, self.rec_path = wr, time.time(), (w, h), path
            self.log(f"[{self.cam['name']}] запись: {path}")
        self._writer.write(frame)

    def _close_writer(self):
        if self._writer is not None:
            try:
                self._writer.release()
            except Exception:
                pass
            self._writer = None


# ======================================================================
#  Раскладки
# ======================================================================
def layout_cells(name, n):
    """Возвращает (ячейки [(x, y, w, h)], столбцов, строк)."""
    n = max(1, n)
    if name == "1+5":
        return [(0, 0, 2, 2), (2, 0, 1, 1), (2, 1, 1, 1), (0, 2, 1, 1), (1, 2, 1, 1), (2, 2, 1, 1)], 3, 3
    if name == "1+7":
        small = [(3, 0), (3, 1), (3, 2), (0, 3), (1, 3), (2, 3), (3, 3)]
        return [(0, 0, 3, 3)] + [(x, y, 1, 1) for x, y in small], 4, 4
    if name in ("1x1", "2x2", "3x3", "4x4"):
        cols = rows = int(name[0])
        cut = None
    else:
        n = min(n, 16)
        cols = math.ceil(math.sqrt(n))
        rows = math.ceil(n / cols)
        cut = n
    cells = [(c, r, 1, 1) for r in range(rows) for c in range(cols)]
    return (cells[:cut] if cut else cells), cols, rows


# ======================================================================
#  Окна
# ======================================================================
class CameraDialog(tk.Toplevel):
    def __init__(self, app, cam):
        super().__init__(app)
        self.app, self.cam, self.result, self.found = app, dict(cam), None, []
        self.title("Камера")
        self.resizable(False, False)
        self.transient(app)
        v = self.vars = {
            "name": tk.StringVar(value=cam["name"]), "ip": tk.StringVar(value=cam["ip"]),
            "port": tk.StringVar(value=str(cam["port"])), "user": tk.StringVar(value=cam["user"]),
            "password": tk.StringVar(value=cam["password"]), "path": tk.StringVar(value=cam["path"]),
            "path_sub": tk.StringVar(value=cam.get("path_sub", "")),
            "enabled": tk.BooleanVar(value=cam.get("enabled", True)),
            "sound": tk.BooleanVar(value=cam.get("sound", False)),
            "record_mode": tk.StringVar(value=cam.get("record_mode", "inherit")),
        }
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)
        rows = [("Название", "name", ""), ("IP-адрес", "ip", ""), ("Порт RTSP", "port", ""),
                ("Логин", "user", ""), ("Пароль", "password", "*")]
        for i, (label, key, show) in enumerate(rows):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="w", pady=2)
            ttk.Entry(f, textvariable=v[key], width=36, show=show).grid(row=i, column=1, sticky="ew", pady=2)
        ttk.Label(f, text="Путь потока (основной)").grid(row=5, column=0, sticky="w", pady=2)
        ttk.Combobox(f, textvariable=v["path"], values=CANDIDATE_PATHS, width=33).grid(row=5, column=1, sticky="ew", pady=2)
        ttk.Label(f, text="Путь суб-потока (для сетки, необязательно)").grid(row=6, column=0, sticky="w", pady=2)
        ttk.Combobox(f, textvariable=v["path_sub"], values=[""] + CANDIDATE_SUB_PATHS, width=33).grid(
            row=6, column=1, sticky="ew", pady=2)
        opts = ttk.Frame(f)
        opts.grid(row=7, column=0, columnspan=2, sticky="w", pady=(2, 0))
        ttk.Checkbutton(opts, text="Камера включена", variable=v["enabled"]).pack(side="left")
        ttk.Checkbutton(opts, text="Звук", variable=v["sound"]).pack(side="left", padx=10)
        ttk.Label(opts, text="Запись:").pack(side="left", padx=(10, 2))
        ttk.Combobox(opts, textvariable=v["record_mode"], width=10, state="readonly",
                     values=["inherit", "always", "motion", "off"]).pack(side="left")
        bf = ttk.Frame(f)
        bf.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ttk.Button(bf, text="Проверить RTSP", command=self.check).pack(side="left")
        ttk.Button(bf, text="Подобрать путь", command=self.auto_path).pack(side="left", padx=4)
        ttk.Button(bf, text="ONVIF: найти потоки", command=self.onvif).pack(side="left")
        self.lb = tk.Listbox(f, height=6, width=62)
        self.lb.grid(row=9, column=0, columnspan=2, sticky="ew")
        self.lb.bind("<<ListboxSelect>>", self.pick)
        lf = ttk.Frame(f)
        lf.grid(row=10, column=0, columnspan=2, sticky="w", pady=(2, 0))
        ttk.Label(lf, text="Выбранный пункт списка →").pack(side="left")
        ttk.Button(lf, text="в основной поток", command=lambda: self.pick(main=True)).pack(side="left", padx=4)
        ttk.Button(lf, text="в суб-поток", command=lambda: self.pick(main=False)).pack(side="left")
        self.msg = tk.StringVar(value="Введите адрес и нажмите «Проверить RTSP» или «ONVIF».")
        ttk.Label(f, textvariable=self.msg, wraplength=430, foreground="#444").grid(
            row=11, column=0, columnspan=2, sticky="w", pady=6)
        bb = ttk.Frame(f)
        bb.grid(row=12, column=0, columnspan=2, sticky="e")
        ttk.Button(bb, text="Сохранить", command=self.ok).pack(side="left", padx=4)
        ttk.Button(bb, text="Отмена", command=self.destroy).pack(side="left")
        self.bind("<Escape>", lambda e: self.destroy())
        self.grab_set()

    def _args(self):
        v = self.vars
        ip = v["ip"].get().strip()
        try:
            port = int(v["port"].get())
        except ValueError:
            self.msg.set("Порт должен быть числом")
            return None
        if not ip:
            self.msg.set("Укажите IP-адрес")
            return None
        return ip, port, v["user"].get(), v["password"].get(), v["path"].get().strip()

    def check(self):
        a = self._args()
        if a:
            self.msg.set("Проверка…")
            self.app.run_bg(lambda: rtsp_probe(*a), self._on_check)

    def _on_check(self, res):
        self.msg.set(f"Ошибка: {res}" if isinstance(res, Exception) else explain_rtsp(*res))

    def auto_path(self):
        a = self._args()
        if a:
            self.msg.set("Перебор типовых путей…")
            self.app.run_bg(lambda: find_paths(a[0], a[1], a[2], a[3]), self._on_paths)

    def _on_paths(self, res):
        if isinstance(res, Exception):
            self.msg.set(f"Ошибка: {res}")
            return
        found, codes = res
        port = int(self.vars["port"].get() or 554)
        self.found = [(p, port) for p, _ in found]
        self.lb.delete(0, "end")
        for p, codec in found:
            self.lb.insert("end", f"{p}   ({codec or 'кодек ?'})")
        if found:
            self.vars["path"].set(found[0][0])
            self.msg.set(f"Найдено рабочих путей: {len(found)}. Выбран {found[0][0]}.")
        elif all(c is None for c in codes):
            self.msg.set("✗ RTSP-порт недоступен. Проверьте IP, порт и включён ли RTSP на камере.")
        elif any(c == 401 for c in codes):
            self.msg.set("✗ Камера отвечает 401: логин или пароль неверны.")
        else:
            self.msg.set("Типовые пути не подошли — нажмите «ONVIF: найти потоки».")

    def onvif(self):
        a = self._args()
        if a:
            self.msg.set("Запрос ONVIF…")
            self.app.run_bg(lambda: onvif_streams(a[0], a[2], a[3]), self._on_onvif)

    def _on_onvif(self, res):
        if isinstance(res, Exception):
            self.msg.set(f"Ошибка: {res}")
            return
        streams, err = res
        self.lb.delete(0, "end")
        self.found = []
        for s in streams:
            self.lb.insert("end", f"{s['name']}   {s['res']} {s['enc']}   →   {s['path']}  (порт {s['port']})")
            self.found.append((s["path"], s["port"]))
        if streams:
            self.vars["path"].set(streams[0]["path"])
            self.vars["port"].set(str(streams[0]["port"]))
            self.msg.set(f"✓ ONVIF вернул потоков: {len(streams)}. Выбран первый — кликните другой при необходимости.")
        else:
            self.msg.set(f"✗ {err}")

    def pick(self, _=None, main=None):
        """main=None — срабатывает по выбору в списке (ставит основной поток);
        main=True/False — явный выбор кнопкой, куда положить путь."""
        sel = self.lb.curselection()
        if sel and sel[0] < len(self.found):
            path, port = self.found[sel[0]]
            if main is False:
                self.vars["path_sub"].set(path)
            else:
                self.vars["path"].set(path)
                self.vars["port"].set(str(port))

    def ok(self):
        a = self._args()
        if not a:
            return
        v = self.vars
        path = a[4] or "/"
        if not path.startswith("/"):
            path = "/" + path
        path_sub = v["path_sub"].get().strip()
        if path_sub and not path_sub.startswith("/"):
            path_sub = "/" + path_sub
        self.result = dict(self.cam, name=v["name"].get().strip() or a[0], ip=a[0], port=a[1],
                           user=a[2], password=a[3], path=path, path_sub=path_sub,
                           enabled=v["enabled"].get(), sound=v["sound"].get(),
                           record_mode=v["record_mode"].get())
        self.destroy()


class ReportWindow(tk.Toplevel):
    def __init__(self, app, title, text):
        super().__init__(app)
        self.title(title)
        self.geometry("820x560")
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Button(bar, text="Копировать", command=self.copy).pack(side="left")
        ttk.Button(bar, text="Закрыть", command=self.destroy).pack(side="left", padx=6)
        self.box = tk.Text(self, wrap="word", font=("Consolas", 10))
        sb = ttk.Scrollbar(self, command=self.box.yview)
        self.box.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.box.pack(fill="both", expand=True)
        self.box.insert("1.0", text)

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.box.get("1.0", "end-1c"))


class RawTcpWindow(tk.Toplevel):
    """Простой «сырой» TCP/telnet-клиент внутри приложения — ручная проверка
    текстовых протоколов (HTTP, SMTP-баннеры, самодельные сервисы и т.п.)
    на найденном узле, без внешних программ."""

    def __init__(self, app, ip, port):
        super().__init__(app)
        self.title(f"Raw TCP {ip}:{port}")
        self.geometry("560x380")
        self.ip, self.port = ip, port
        self.sock = None
        self.q = queue.Queue()
        self.text = tk.Text(self, state="disabled", bg="#0d1117", fg="#c9d1d9",
                            insertbackground="#c9d1d9")
        self.text.pack(fill="both", expand=True, padx=4, pady=(4, 0))
        row = ttk.Frame(self, padding=4)
        row.pack(fill="x")
        self.entry = ttk.Entry(row)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", self.send)
        ttk.Button(row, text="Отправить", command=self.send).pack(side="left", padx=4)
        self.protocol("WM_DELETE_WINDOW", self.close)
        threading.Thread(target=self._connect, daemon=True).start()
        self.after(100, self._poll)

    def _append(self, s):
        self.q.put(s)

    def _connect(self):
        try:
            self.sock = socket.create_connection((self.ip, self.port), timeout=4)
            self.sock.settimeout(0.3)
            self._append(f"Подключено к {self.ip}:{self.port}\n")
            while True:
                try:
                    data = self.sock.recv(4096)
                    if not data:
                        self._append("\n[соединение закрыто удалённой стороной]\n")
                        break
                    self._append(data.decode(errors="replace"))
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception as e:
            self._append(f"Ошибка подключения: {e}\n")

    def send(self, _=None):
        line = self.entry.get()
        self.entry.delete(0, "end")
        if self.sock:
            try:
                self.sock.sendall((line + "\r\n").encode())
                self._append(f"> {line}\n")
            except OSError as e:
                self._append(f"Ошибка отправки: {e}\n")
        else:
            self._append("[не подключено]\n")

    def _poll(self):
        try:
            while True:
                s = self.q.get_nowait()
                self.text.configure(state="normal")
                self.text.insert("end", s)
                self.text.see("end")
                self.text.configure(state="disabled")
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(100, self._poll)

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.destroy()


class TopologyWindow(tk.Toplevel):
    """Визуализация топологии сети на Canvas: узлы (этот ПК, шлюз/коммутаторы,
    камеры, NAS, принтеры, ПК, IoT, неизвестные устройства) цветом по типу,
    связи между ними линиями (с подписью порта, если известен). Колесо мыши
    или кнопки +/- - зум, перетаскивание ЛКМ - панорамирование, экспорт в
    Graphviz DOT или в изображение (PostScript)."""

    def __init__(self, app, topo, title="Топология сети"):
        super().__init__(app)
        self.app = app
        self.title(title)
        self.geometry("1020x660")
        self.topo = topo

        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Button(bar, text="−", width=3, command=lambda: self._zoom(0.85)).pack(side="left")
        ttk.Button(bar, text="+", width=3, command=lambda: self._zoom(1.15)).pack(side="left", padx=(2, 10))
        ttk.Button(bar, text="Экспорт в Graphviz (.dot)", command=self.export_dot).pack(side="left")
        ttk.Button(bar, text="Сохранить изображение (.ps)", command=self.export_ps).pack(side="left", padx=6)
        self.info = tk.StringVar(
            value=f"Узлов: {len(topo['nodes'])}, связей: {len(topo['edges'])}")
        ttk.Label(bar, textvariable=self.info, foreground="#888").pack(side="left", padx=10)

        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(wrap, bg="#0d1117", highlightthickness=0)
        hbar = ttk.Scrollbar(wrap, orient="horizontal", command=self.canvas.xview)
        vbar = ttk.Scrollbar(wrap, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(xscrollcommand=hbar.set, yscrollcommand=vbar.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        self.canvas.bind("<ButtonPress-1>", lambda e: self.canvas.scan_mark(e.x, e.y))
        self.canvas.bind("<B1-Motion>", lambda e: self.canvas.scan_dragto(e.x, e.y, gain=1))
        self.canvas.bind("<MouseWheel>", lambda e: self._zoom(1.1 if e.delta > 0 else 0.9))
        self.canvas.bind("<Button-4>", lambda e: self._zoom(1.1))   # Linux, колесо вверх
        self.canvas.bind("<Button-5>", lambda e: self._zoom(0.9))   # Linux, колесо вниз

        if not topo["nodes"]:
            self.info.set("Топология пуста — узлов не найдено.")
        self.draw()
        errs = topo.get("errors")
        if errs:
            self.app.log("Топология: " + "; ".join(errs))

    def _zoom(self, factor):
        self.canvas.scale("all", 0, 0, factor, factor)
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def draw(self):
        self.canvas.delete("all")
        pos = topology.layout(self.topo["nodes"], self.topo["edges"])
        if not pos:
            return
        xs = [p[0] for p in pos.values()]
        ys = [p[1] for p in pos.values()]
        off_x = 480 - (min(xs) + max(xs)) / 2
        off_y = 50 - min(ys)

        for e in self.topo["edges"]:
            a, b = e[0], e[1]
            if a not in pos or b not in pos:
                continue
            ax, ay = pos[a][0] + off_x, pos[a][1] + off_y
            bx, by = pos[b][0] + off_x, pos[b][1] + off_y
            self.canvas.create_line(ax, ay, bx, by, fill="#30363d", width=2)
            if len(e) > 2 and e[2]:
                self.canvas.create_text((ax + bx) / 2, (ay + by) / 2 - 8, text=e[2],
                                        fill="#8b949e", font=("Segoe UI", 8))

        w, h = 130, 46
        for key, n in self.topo["nodes"].items():
            if key not in pos:
                continue
            x, y = pos[key][0] + off_x, pos[key][1] + off_y
            color = topology.NODE_COLORS.get(n.get("type", "unknown"), "#9aa5b1")
            self.canvas.create_rectangle(x - w / 2, y - h / 2, x + w / 2, y + h / 2,
                                         fill=color, outline="#c9d1d9", width=1)
            self.canvas.create_text(x, y, text=n.get("label", key), fill="#0d1117",
                                    font=("Segoe UI", 9, "bold"), justify="center", width=w - 10)
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def export_dot(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".dot",
                                            filetypes=[("Graphviz DOT", "*.dot")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(topology.export_dot(self.topo, self.title()))
            self.info.set(f"Экспортировано: {path}")
        except OSError as e:
            self.info.set(f"Ошибка экспорта: {e}")

    def export_ps(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".ps",
                                            filetypes=[("PostScript", "*.ps")])
        if not path:
            return
        try:
            self.canvas.postscript(file=path, colormode="color")
            self.info.set(f"Сохранено: {path}")
        except Exception as e:
            self.info.set(f"Ошибка сохранения: {e}")


class ScanWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Поиск и идентификация узлов сети")
        self.geometry("1060x540")
        self.progress = {"done": 0, "total": 0}
        self.busy = False
        self.rows = {}
        self._scan_queue = []
        self._current_net = None
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        self.cidr = tk.StringVar(value=self._default_cidr())
        ttk.Label(top, text="Подсеть (например 10.0.0, 192.168.1.x или CIDR до /16):").pack(side="left")
        ttk.Entry(top, textvariable=self.cidr, width=22).pack(side="left", padx=4)
        ttk.Button(top, text="Сканировать порты", command=self.scan).pack(side="left")
        ttk.Button(top, text="Мои сети 10.x.x.x", command=self.scan_my_10).pack(side="left", padx=4)
        ttk.Button(top, text="ONVIF-поиск", command=self.discover).pack(side="left")
        ttk.Button(top, text="SSDP/UPnP-поиск", command=self.discover_ssdp).pack(side="left", padx=4)
        ttk.Button(top, text="mDNS/Bonjour-поиск", command=self.discover_mdns).pack(side="left")
        ttk.Button(top, text="Подобрать пароли", command=self.guess_all).pack(side="left", padx=4)

        top2 = ttk.Frame(self, padding=(8, 0))
        top2.pack(fill="x")
        ttk.Button(top2, text="Определить устройства (вендор/ОС/тип)",
                   command=self.identify_all).pack(side="left")
        ttk.Button(top2, text="Оценить риск", command=self.assess_risk).pack(side="left", padx=6)
        self.risk_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(top2, variable=self.risk_only, text="Показывать только рискованные",
                        command=self._render).pack(side="left")
        ttk.Button(top2, text="Подключиться к выбранному…", command=lambda: self.connect_to()).pack(
            side="left", padx=6)
        ttk.Button(top2, text="Экспорт CSV/JSON…", command=self.export).pack(side="left")
        ttk.Button(top2, text="Локальная топология", command=self.show_local_topology).pack(
            side="left", padx=(16, 0))
        ttk.Button(top2, text="Топология через SNMP…", command=self.show_snmp_topology).pack(
            side="left", padx=4)
        ttk.Button(top2, text="Пассивная топология (LLDP/CDP)…", command=self.show_passive_topology).pack(
            side="left", padx=4)

        presets = ttk.Frame(self, padding=(8, 0))
        presets.pack(fill="x")
        ttk.Label(presets, text="Быстрый выбор:").pack(side="left")
        for label, cidr in (("Моя подсеть", self._my_cidr()), ("10.0.0.0/16", "10.0.0.0/16"),
                             ("10.10.0.0/16", "10.10.0.0/16"), ("192.168.0.0/16", "192.168.0.0/16")):
            if cidr:
                ttk.Button(presets, text=label, command=lambda c=cidr: self.cidr.set(c)).pack(side="left", padx=2)

        self.confirm_owner = tk.BooleanVar(value=False)
        ttk.Checkbutton(presets, variable=self.confirm_owner,
                        text="Это моя сеть или у меня есть разрешение на её аудит "
                             f"(обязательно для сетей больше {SCAN_CONFIRM_HOSTS} адресов)").pack(
            side="left", padx=(16, 0))

        self.status = tk.StringVar(value="Укажите подсеть (10.0.0, 192.168.1.x или CIDR) и нажмите «Сканировать порты».")
        ttk.Label(self, textvariable=self.status, padding=(8, 0), wraplength=1040).pack(fill="x")
        self.tree = ttk.Treeview(
            self, columns=("ip", "mac", "vendor", "type", "ports", "info", "cred", "risk"), show="headings")
        for col, text, w in (("ip", "IP", 110), ("mac", "MAC", 130), ("vendor", "Производитель", 110),
                             ("type", "Тип устройства", 150), ("ports", "Открытые порты", 120),
                             ("info", "Доп. инфо / баннер", 220), ("cred", "Логин / пароль", 140),
                             ("risk", "Риск", 70)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=w)
        self.tree.tag_configure("found", foreground="#19c37d")
        self.tree.tag_configure("risk_high", foreground=risk.level_color("высокий"))
        self.tree.tag_configure("risk_med", foreground=risk.level_color("средний"))
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)
        self.tree.bind("<Double-1>", lambda e: self.add_selected())
        self.tree.bind("<Button-3>", self._on_right_click)

        bottom = ttk.Frame(self, padding=(8, 0))
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Добавить выбранную как камеру…", command=self.add_selected).pack(side="left")
        ttk.Button(bottom, text="Добавить все найденные камеры", command=self.add_all_found).pack(
            side="left", padx=6)
        ttk.Label(bottom, foreground="#888",
                  text="Правый клик по строке — меню подключения (SSH/веб/RDP/VNC/raw TCP) к ЛЮБОМУ узлу.",
                  ).pack(side="left", padx=12)

        ttk.Label(self, foreground="#888",
                  text="«Подобрать пароли» проверяет только типовые заводские пары (admin/admin и т.п., "
                       "для любых производителей — Tiandy, Hikvision, Dahua, Reolink и др.) на уже найденных "
                       "в этой сети устройствах. Сканируйте, подбирайте пароли и подключайтесь ТОЛЬКО к "
                       "оборудованию, которым вы владеете или на проверку которого у вас есть разрешение — "
                       "несанкционированный доступ к чужим устройствам запрещён законом.",
                  wraplength=1040).pack(fill="x", padx=8, pady=(0, 6))

    def _my_cidr(self):
        for ip in local_ips():
            try:
                return str(ipaddress.ip_network(f"{ip}/24", strict=False))
            except ValueError:
                continue
        return ""

    def _default_cidr(self):
        s = self.app.settings
        for cam in self.app.cfg["cameras"]:
            if not cam.get("ip"):
                continue
            try:
                return str(ipaddress.ip_network(f"{cam['ip']}/{s.get('netmask') or '255.255.255.0'}", strict=False))
            except ValueError:
                continue
        return self._my_cidr() or "192.168.1.0/24"

    def _tick(self):
        if self.busy and self.winfo_exists():
            extra = f" ({self._current_net})" if self._current_net else ""
            self.status.set(f"Сканирование{extra}… {self.progress['done']}/{self.progress['total']}")
            self.after(200, self._tick)

    def scan(self):
        if self.busy:
            return
        try:
            net = parse_subnet_input(self.cidr.get())
        except ValueError:
            self.status.set("Неверная подсеть. Примеры: 10.0.0.0/24, 10.0.0, 192.168.1.x, 10.0.0.0/16")
            return
        if net.num_addresses > SCAN_MAX_HOSTS:
            self.status.set(f"Слишком большая сеть ({net}, максимум {SCAN_MAX_HOSTS} адресов, "
                            f"это ≈ сеть /16) — сузьте диапазон, например {net.network_address}/16, "
                            "и при необходимости просканируйте соседние блоки отдельно.")
            return
        if net.num_addresses > SCAN_CONFIRM_HOSTS and not self.confirm_owner.get():
            self.status.set(f"Сеть {net} содержит {net.num_addresses} адресов — отметьте галочку "
                            "«Это моя сеть…» выше, чтобы подтвердить, что у вас есть право её сканировать.")
            return
        self.busy = True
        self._current_net = str(net)
        self._tick()
        self.app.run_bg(lambda: scan_subnet(str(net), self.progress), self._on_scan)

    def scan_my_10(self):
        """Сканирует ВСЕ сети 10.x.x.x, к которым компьютер подключён прямо сейчас
        (через любой сетевой адаптер) — то есть только те 10.x.x.x-сети, доступ
        к которым у пользователя уже есть по факту. Не требует ручного ввода
        подсети и не трогает остальной гигантский блок 10.0.0.0/8, к которому
        компьютер не подключён."""
        if self.busy:
            return
        nets = my_10_networks()
        if not nets:
            self.status.set("Не нашёл ни одной сети 10.x.x.x — ни на адаптерах компьютера, ни в "
                            "таблице маршрутизации. Если камера на 10.x.x.x в той же L2-сети за "
                            "обычным (неуправляемым) коммутатором без отдельного маршрута, "
                            "добавьте компьютеру второй IP-адрес в сети 10.x.x.x в настройках "
                            "сетевого адаптера и повторите, либо укажите подсеть вручную ниже.")
            return
        total_hosts = sum(ipaddress.ip_network(n).num_addresses for n in nets)
        if total_hosts > SCAN_MAX_HOSTS:
            self.status.set(f"Суммарно подключённые сети 10.x.x.x слишком большие "
                            f"({total_hosts} адресов) — просканируйте их по одной через поле "
                            f"подсети: {', '.join(nets)}")
            return
        self.busy = True
        self._scan_queue = list(nets)
        self.status.set(f"Найдены подключённые сети: {', '.join(nets)} — сканирую…")
        self._tick()
        self._scan_next()

    def _scan_next(self):
        if not self._scan_queue:
            self.busy = False
            self._current_net = None
            self.status.set(f"Готово: просканированы мои сети 10.x.x.x, найдено устройств: {len(self.rows)}.")
            self._render()
            return
        self._current_net = self._scan_queue.pop(0)
        self.progress = {"done": 0, "total": 0}
        self.app.run_bg(lambda n=self._current_net: scan_subnet(n, self.progress), self._on_scan_step)

    def _on_scan_step(self, res):
        if not isinstance(res, Exception):
            for ip, d in res.items():
                row = self.rows.setdefault(ip, {"ports": [], "info": ""})
                row["ports"] = d["ports"]
                row["info"] = d["info"] or row["info"]
            self._merge_arp()
            self._render()
        else:
            self.app.log(f"Скан {self._current_net}: ошибка {res}")
        self._scan_next()

    def _on_scan(self, res):
        self.busy = False
        self._current_net = None
        if isinstance(res, Exception):
            self.status.set(f"Ошибка: {res}")
            return
        for ip, d in res.items():
            row = self.rows.setdefault(ip, {"ports": [], "info": ""})
            row["ports"] = d["ports"]
            row["info"] = d["info"] or row["info"]
        self._merge_arp()
        self.status.set(f"Найдено устройств с открытыми портами: {len(res)}")
        self._render()

    def _merge_arp(self):
        """Дополняет уже найденные строки MAC-адресом из системной ARP-таблицы
        (быстрая локальная операция, без сетевых запросов)."""
        try:
            arp = netid.read_arp_table()
        except Exception:
            return
        for ip, r in self.rows.items():
            if not r.get("mac"):
                r["mac"] = arp.get(ip, "")

    def discover(self):
        self.status.set("ONVIF-поиск (3 сек)…")
        self.app.run_bg(ws_discovery, self._on_discover)

    def _on_discover(self, res):
        if isinstance(res, Exception):
            self.status.set(f"Ошибка: {res}")
            return
        for ip, d in res.items():
            row = self.rows.setdefault(ip, {"ports": [], "info": ""})
            row["info"] = ("ONVIF: " + " ".join(x for x in (d["name"], d["hw"]) if x)).strip() + \
                          ((" | " + row["info"]) if row["info"] else "")
        self.status.set(f"ONVIF-камер найдено: {len(res)}" if res else
                        "ONVIF-ответов нет (мультикаст может не проходить — используйте скан портов)")
        self._render()

    def discover_ssdp(self):
        """UPnP/SSDP-поиск — находит роутеры, NAS, медиасерверы, умные
        устройства и т.п., не только камеры."""
        if self.busy:
            return
        self.busy = True
        self.status.set("SSDP/UPnP-поиск (3 сек)…")
        self.app.run_bg(lambda: netid.ssdp_discover(3.0), self._on_ssdp)

    def _on_ssdp(self, res):
        self.busy = False
        if isinstance(res, Exception):
            self.status.set(f"Ошибка SSDP: {res}")
            return
        for ip, d in res.items():
            row = self.rows.setdefault(ip, {"ports": [], "info": ""})
            tag = f"SSDP: {d['server']}" if d.get("server") else "SSDP"
            if tag not in (row.get("info") or ""):
                row["info"] = (row["info"] + " | " if row["info"] else "") + tag
        self._merge_arp()
        self.status.set(f"SSDP-ответов: {len(res)}" if res else
                        "SSDP-ответов нет (мультикаст может не проходить).")
        self._render()

    def discover_mdns(self):
        """mDNS/Bonjour-поиск — принтеры AirPrint, Chromecast, умные колонки/
        AirPlay, Apple-устройства и т.п., которые часто не отвечают на SSDP."""
        if self.busy:
            return
        self.busy = True
        self.status.set("mDNS/Bonjour-поиск (3 сек)…")
        self.app.run_bg(lambda: netid.mdns_discover(3.0), self._on_mdns)

    def _on_mdns(self, res):
        self.busy = False
        if isinstance(res, Exception):
            self.status.set(f"Ошибка mDNS: {res}")
            return
        for ip, d in res.items():
            services = d.get("services") or []
            row = self.rows.setdefault(ip, {"ports": [], "info": ""})
            tag = ("mDNS: " + ", ".join(services)) if services else "mDNS"
            if tag not in (row.get("info") or ""):
                row["info"] = (row["info"] + " | " if row["info"] else "") + tag
            if services and not row.get("device_type"):
                row["device_type"] = "Устройство с mDNS/Bonjour"
        self._merge_arp()
        self.status.set(f"mDNS-ответов: {len(res)}" if res else
                        "mDNS-ответов нет (мультикаст может не проходить).")
        self._render()

    def assess_risk(self):
        """Пассивная оценка риска уже найденных узлов: небезопасные протоколы
        (telnet/FTP/SMBv1 и т.п.), веб-интерфейс без авторизации, проблемы
        TLS-сертификата. Ничего не подбирает и никуда не логинится."""
        if self.busy:
            return
        targets = [ip for ip, r in self.rows.items() if r.get("ports")]
        if not targets:
            self.status.set("Сначала выполните скан — оценивать риск пока не на чем.")
            return
        self.busy = True
        self.status.set(f"Оцениваю риск {len(targets)} узлов (порты/баннеры/TLS)…")

        def work():
            def one(ip):
                r = self.rows[ip]
                host = {"ip": ip, "ports": r.get("ports", []), "banner": r.get("info", ""),
                       "http": r.get("http", {})}
                return ip, risk.assess_risk(host, timeout=2.0)
            with ThreadPoolExecutor(min(16, len(targets))) as ex:
                return list(ex.map(one, targets))

        self.app.run_bg(work, self._on_risk)

    def _on_risk(self, res):
        self.busy = False
        if isinstance(res, Exception):
            self.status.set(f"Ошибка оценки риска: {res}")
            return
        counts = {"низкий": 0, "средний": 0, "высокий": 0}
        for ip, r in res:
            self.rows.setdefault(ip, {"ports": [], "info": ""})["risk"] = r
            counts[r["level"]] = counts.get(r["level"], 0) + 1
        self.status.set(f"Риск оценён: высокий — {counts['высокий']}, средний — {counts['средний']}, "
                        f"низкий — {counts['низкий']}.")
        self._render()

    def identify_all(self):
        """Определяет производителя (MAC/OUI), догадку ОС, NetBIOS-имя, SNMP
        sysDescr и итоговый тип устройства для уже найденных узлов."""
        if self.busy:
            return
        targets = [ip for ip, r in self.rows.items() if not r.get("identified")]
        if not targets:
            self.status.set("Нет новых узлов для определения — сначала выполните скан, "
                            "либо все уже определены.")
            return
        self.busy = True
        self.status.set(f"Определяю тип устройства у {len(targets)} узлов (MAC/ОС/SNMP/баннеры)…")

        def work():
            def one(ip):
                r = self.rows[ip]
                return ip, netid.identify_host(ip, r.get("ports", []), mac=r.get("mac"), timeout=1.0)
            with ThreadPoolExecutor(min(24, len(targets))) as ex:
                return list(ex.map(one, targets))

        self.app.run_bg(work, self._on_identify)

    def _on_identify(self, res):
        self.busy = False
        if isinstance(res, Exception):
            self.status.set(f"Ошибка определения: {res}")
            return
        for ip, d in res:
            row = self.rows.setdefault(ip, {"ports": [], "info": ""})
            row["identified"] = True
            row["mac"] = d.get("mac") or row.get("mac", "")
            row["vendor"] = d.get("vendor", "")
            row["device_type"] = d.get("device_type", "")
            row["os_guess"] = d.get("os_guess", "")
            if d.get("banner") and d["banner"] not in (row.get("info") or ""):
                row["info"] = (row["info"] + " | " if row["info"] else "") + d["banner"]
        self.status.set(f"Определение завершено для {len(res)} узлов.")
        self._render()

    def export(self):
        if not self.rows:
            self.status.set("Нечего экспортировать — сначала выполните скан.")
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        rows = []
        for ip in sorted(self.rows, key=lambda x: tuple(int(p) for p in x.split("."))):
            r = self.rows[ip]
            risk_info = r.get("risk") or {}
            rows.append({
                "ip": ip, "mac": r.get("mac", ""), "vendor": r.get("vendor", ""),
                "device_type": r.get("device_type", ""), "os_guess": r.get("os_guess", ""),
                "ports": ",".join(map(str, r.get("ports", []))), "info": r.get("info", ""),
                "risk_level": risk_info.get("level", ""),
                "risk_reasons": "; ".join(risk_info.get("reasons", [])),
            })
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(rows, f, ensure_ascii=False, indent=2)
            else:
                fields = list(rows[0].keys()) if rows else \
                    ["ip", "mac", "vendor", "device_type", "os_guess", "ports", "info",
                     "risk_level", "risk_reasons"]
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=fields)
                    w.writeheader()
                    w.writerows(rows)
            self.status.set(f"Экспортировано: {path}")
        except OSError as e:
            self.status.set(f"Ошибка экспорта: {e}")

    # ---- топология сети ----
    def show_local_topology(self):
        """«Логическая» топология без опроса коммутаторов: этот компьютер,
        шлюз и уже найденные узлы — из того, что уже видно по скану/ARP."""
        if not self.rows:
            self.status.set("Сначала выполните скан — топологии не из чего строить.")
            return
        hosts = [dict(r, ip=ip) for ip, r in self.rows.items()]
        self.status.set("Строю локальную топологию…")

        def work():
            return topology.build_local_topology(
                hosts, my_ip=netid.local_ip(), gateway_ip=netid.default_gateway())

        self.app.run_bg(work, self._on_local_topology)

    def _on_local_topology(self, res):
        if isinstance(res, Exception):
            self.status.set(f"Ошибка построения топологии: {res}")
            return
        self.status.set(f"Локальная топология: {len(res['nodes'])} узлов.")
        TopologyWindow(self.app, res, title="Локальная топология сети")

    def show_snmp_topology(self):
        """Реальная топология через коммутаторы: обход LLDP-соседей и
        MAC-таблиц портов по SNMP. Нужны управляемые коммутаторы с
        включённым SNMP (read-only community, часто по умолчанию 'public')."""
        seed = simpledialog.askstring(
            "Топология через SNMP",
            "IP-адрес(а) управляемого коммутатора через запятую:",
            parent=self)
        if not seed:
            return
        community = simpledialog.askstring(
            "Топология через SNMP", "SNMP community:", initialvalue="public", parent=self)
        if community is None:
            return
        seeds = [s.strip() for s in seed.split(",") if s.strip()]
        hosts = [dict(r, ip=ip) for ip, r in self.rows.items()]
        self.status.set(f"Опрашиваю по SNMP: {', '.join(seeds)} (LLDP + MAC-таблицы)…")

        def work():
            return topology.build_snmp_topology(seeds, community=community or "public", hosts=hosts)

        self.app.run_bg(work, self._on_snmp_topology)

    def _on_snmp_topology(self, res):
        if isinstance(res, Exception):
            self.status.set(f"Ошибка SNMP-топологии: {res}")
            return
        self.status.set(f"SNMP-топология: {len(res['nodes'])} узлов, {len(res['edges'])} связей"
                        + (f" — проблемы: {len(res['errors'])}" if res.get("errors") else "."))
        TopologyWindow(self.app, res, title="Топология через SNMP (LLDP/MAC-таблицы)")

    def show_passive_topology(self):
        """Топология через пассивное прослушивание LLDP/CDP — без SNMP-доступа
        к коммутатору, но требует прав администратора/root и, на Windows,
        установленного Npcap."""
        if not topology.SCAPY_AVAILABLE:
            messagebox.showinfo(
                "Пассивная топология",
                "Для этой функции нужен пакет scapy (pip install scapy) — "
                "он не установлен.", parent=self)
            return
        if not topology.has_sniff_privileges():
            hint = " и установленный Npcap (npcap.com)" if os.name == "nt" else ""
            messagebox.showwarning(
                "Пассивная топология",
                f"Нужны права администратора/root{hint}. Перезапустите приложение "
                "с повышенными правами и повторите.", parent=self)
            return
        duration = simpledialog.askinteger(
            "Пассивная топология (LLDP/CDP)",
            "Сколько секунд слушать эфир? (коммутаторы обычно рассылают кадры "
            "раз в ~30 сек, так что меньше 30-60 сек почти ничего не поймает)",
            initialvalue=60, minvalue=5, maxvalue=600, parent=self)
        if not duration:
            return
        hosts = [dict(r, ip=ip) for ip, r in self.rows.items()]
        self.status.set(f"Слушаю LLDP/CDP {duration} сек (без SNMP-опроса)…")

        def work():
            return topology.build_passive_topology(duration=duration, hosts=hosts)

        self.app.run_bg(work, self._on_passive_topology)

    def _on_passive_topology(self, res):
        if isinstance(res, Exception):
            self.status.set(f"Ошибка пассивной топологии: {res}")
            return
        self.status.set(f"Пассивная топология: {len(res['nodes'])} узлов, {len(res['edges'])} связей"
                        + (f" — см. предупреждения." if res.get("errors") else "."))
        if res.get("errors") and not res["nodes"]:
            messagebox.showwarning("Пассивная топология", "\n".join(res["errors"]), parent=self)
            return
        TopologyWindow(self.app, res, title="Пассивная топология (LLDP/CDP)")

    # ---- подключение к ЛЮБОМУ найденному узлу (не только камере) ----
    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.connect_to(iid)

    def connect_to(self, ip=None):
        ip = ip or (self.tree.selection()[0] if self.tree.selection() else None)
        if not ip or ip not in self.rows:
            self.status.set("Выберите узел в списке.")
            return
        ports = self.rows[ip].get("ports", [])
        menu = tk.Menu(self, tearoff=0)
        added = False
        if 22 in ports:
            menu.add_command(label="SSH", command=lambda: self._launch_ssh(ip)); added = True
        if 23 in ports:
            menu.add_command(label="Telnet", command=lambda: self._launch_telnet(ip)); added = True
        for p, scheme in ((80, "http"), (8080, "http"), (8000, "http"),
                          (443, "https"), (8443, "https")):
            if p in ports:
                menu.add_command(label=f"Открыть {scheme}://{ip}:{p} в браузере",
                                 command=lambda s=scheme, p=p: webbrowser.open(f"{s}://{ip}:{p}"))
                added = True
        if 3389 in ports:
            menu.add_command(label="RDP", command=lambda: self._launch_rdp(ip)); added = True
        if 5900 in ports:
            menu.add_command(label="VNC", command=lambda: self._launch_vnc(ip)); added = True
        if 445 in ports or 139 in ports:
            menu.add_command(label="Открыть сетевую папку (SMB)",
                             command=lambda: self._launch_smb(ip)); added = True
        if ports:
            menu.add_separator()
        for p in ports:
            menu.add_command(label=f"Raw TCP: порт {p}",
                             command=lambda p=p: RawTcpWindow(self.app, ip, p))
            added = True
        menu.add_command(label="Raw TCP: другой порт…", command=lambda: self._raw_tcp_ask(ip))
        menu.add_separator()
        menu.add_command(label="Добавить как камеру…",
                         command=lambda: (self.tree.selection_set(ip), self.add_selected()))
        if self.rows.get(ip, {}).get("risk"):
            menu.add_command(label="Подробнее о риске…", command=lambda: self._show_risk_detail(ip))
        try:
            menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally:
            menu.grab_release()

    def _launch_ssh(self, ip):
        if not shutil.which("ssh"):
            messagebox.showinfo("SSH", "Клиент ssh не найден в PATH.")
            return
        user = simpledialog.askstring("SSH", "Пользователь:", parent=self) or ""
        target = f"{user}@{ip}" if user else ip
        self._spawn_console(["ssh", target])

    def _launch_telnet(self, ip):
        if not shutil.which("telnet"):
            messagebox.showinfo("Telnet", "Клиент telnet не найден в PATH.")
            return
        self._spawn_console(["telnet", ip])

    def _launch_rdp(self, ip):
        if os.name == "nt":
            subprocess.Popen(["mstsc", f"/v:{ip}"])
        elif shutil.which("xfreerdp"):
            user = simpledialog.askstring("RDP", "Пользователь:", parent=self) or ""
            self._spawn_console(["xfreerdp", f"/v:{ip}", f"/u:{user}"])
        else:
            messagebox.showinfo("RDP", "Не найден RDP-клиент (mstsc на Windows или xfreerdp).")

    def _launch_vnc(self, ip):
        for name in ("vncviewer", "vinagre", "remmina"):
            if shutil.which(name):
                subprocess.Popen([name, ip])
                return
        messagebox.showinfo("VNC", "VNC-клиент (vncviewer/remmina) не найден в PATH.")

    def _launch_smb(self, ip):
        if os.name == "nt":
            subprocess.Popen(["explorer", fr"\\{ip}"])
        else:
            for name in ("nautilus", "dolphin", "xdg-open"):
                if shutil.which(name):
                    subprocess.Popen([name, f"smb://{ip}/"])
                    return
            messagebox.showinfo("SMB", f"Откройте в файловом менеджере: smb://{ip}/")

    def _spawn_console(self, cmd):
        try:
            if os.name == "nt":
                subprocess.Popen(["cmd", "/c", "start", "", *cmd])
            else:
                for term in ("x-terminal-emulator", "gnome-terminal", "konsole", "xterm"):
                    if shutil.which(term):
                        if term == "gnome-terminal":
                            subprocess.Popen([term, "--", *cmd])
                        else:
                            subprocess.Popen([term, "-e", " ".join(cmd)])
                        return
                messagebox.showinfo("Подключение", "Не найден терминал. Команда: " + " ".join(cmd))
        except Exception as e:
            messagebox.showerror("Ошибка подключения", str(e))

    def _show_risk_detail(self, ip):
        r = self.rows.get(ip, {}).get("risk")
        if not r:
            return
        text = f"Уровень риска: {r['level']}\n\n" + "\n".join(f"• {reason}" for reason in r["reasons"])
        messagebox.showinfo(f"Риск узла {ip}", text, parent=self)

    def _raw_tcp_ask(self, ip):
        port = simpledialog.askinteger("Raw TCP", "Порт:", parent=self)
        if port:
            RawTcpWindow(self.app, ip, port)

    def _render(self):
        self.tree.delete(*self.tree.get_children())
        only_risky = self.risk_only.get()
        # Отдаём в главное окно сводку для NOC-статус-бара: сколько узлов
        # сейчас видно и агрегированный уровень угрозы по уже оценённым
        # (risk) узлам. Только отображение - сами данные не меняются.
        counts = {"низкий": 0, "средний": 0, "высокий": 0}
        for r in self.rows.values():
            ri = r.get("risk")
            if ri:
                counts[ri["level"]] = counts.get(ri["level"], 0) + 1
        self.app.update_watch_summary(nodes=len(self.rows), risk_counts=counts)
        for ip in sorted(self.rows, key=lambda x: tuple(int(p) for p in x.split("."))):
            r = self.rows[ip]
            risk_info = r.get("risk")
            risk_level = risk_info["level"] if risk_info else ""
            if only_risky and risk_level not in ("средний", "высокий"):
                continue
            cred = r.get("cred")
            cred_s = f"{cred['user']} / {cred['password'] or '(пусто)'}  [{cred['via']}]" if cred else ""
            tags = []
            if cred:
                tags.append("found")
            if risk_level == "высокий":
                tags.append("risk_high")
            elif risk_level == "средний":
                tags.append("risk_med")
            self.tree.insert(
                "", "end", iid=ip,
                values=(ip, r.get("mac", ""), r.get("vendor", ""), r.get("device_type", ""),
                       ", ".join(map(str, r["ports"])), r["info"], cred_s, risk_level),
                tags=tuple(tags))

    # ---- подбор типовых логинов/паролей на уже найденных устройствах
    def guess_all(self):
        if self.busy:
            return
        targets = [ip for ip, r in self.rows.items()
                   if r["ports"] and not r.get("cred") and not r.get("cred_tried")]
        if not targets:
            self.status.set("Сначала выполните «Сканировать порты» (или ONVIF-поиск), затем подбор паролей.")
            return
        self.busy = True
        self.status.set(f"Подбор типовых логинов/паролей на {len(targets)} устройствах…")

        def work():
            def one(ip):
                r = self.rows[ip]
                rtsp_port = next((p for p in (554, 8554, 10554) if p in r["ports"]), None)
                return ip, guess_credentials(ip, rtsp_port)
            with ThreadPoolExecutor(min(8, len(targets))) as ex:
                return list(ex.map(one, targets))

        self.app.run_bg(work, self._on_guess)

    def _on_guess(self, res):
        self.busy = False
        if isinstance(res, Exception):
            self.status.set(f"Ошибка подбора: {res}")
            return
        found = 0
        for ip, cred in res:
            self.rows[ip]["cred_tried"] = True
            if cred:
                self.rows[ip]["cred"] = cred
                found += 1
        self.status.set(f"Подбор завершён: подошли пароли у {found} из {len(res)} устройств.")
        self._render()

    def add_selected(self):
        sel = self.tree.selection()
        if not sel:
            self.status.set("Выберите строку в списке.")
            return
        ip = sel[0]
        r = self.rows[ip]
        port = next((p for p in (554, 8554, 10554) if p in r["ports"]), 554)
        prefill = {"ip": ip, "port": port, "name": f"Камера {ip.split('.')[-1]}"}
        cred = r.get("cred")
        if cred:
            prefill["user"] = cred["user"]
            prefill["password"] = cred["password"]
            prefill["path"] = cred["path"]
            prefill["port"] = cred["port"]
        self.app.add_camera(prefill=prefill)

    def add_all_found(self):
        """Добавляет в просмотр СРАЗУ все найденные камеры, у которых подобран
        рабочий логин/пароль (кнопка «Подобрать пароли») — без диалога на каждую,
        чтобы реально можно было одним кликом подключить все камеры с заводскими
        паролями, обнаруженные при скане своей сети."""
        targets = [ip for ip, r in self.rows.items() if r.get("cred")]
        if not targets:
            self.status.set("Пока нет камер с подобранным паролем. Сначала «Сканировать порты», "
                            "затем «Подобрать пароли».")
            return
        existing = {(c["ip"], int(c.get("port") or 554)) for c in self.app.cfg["cameras"]}
        added, skipped = 0, 0
        for ip in sorted(targets, key=lambda x: tuple(int(p) for p in x.split("."))):
            cred = self.rows[ip]["cred"]
            port = int(cred["port"])
            if (ip, port) in existing:
                skipped += 1
                continue
            name = f"{self.rows[ip]['info'].split('|')[0].strip() or 'Камера'} {ip}"
            cam = new_camera(name=name[:60], ip=ip, port=port, user=cred["user"],
                             password=cred["password"], path=cred["path"])
            self.app.cfg["cameras"].append(cam)
            existing.add((ip, port))
            added += 1
        if added:
            self.app.after_change()
            self.app.log(f"Поиск камер: добавлено {added} камер(ы) со скомпрометированными "
                         f"заводскими паролями ({', '.join(sorted(targets))}).")
        self.status.set(f"Добавлено камер: {added}." + (f" Уже были в списке: {skipped}." if skipped else ""))


class AnalysisWindow(tk.Toplevel):
    COLS = [("name", "Камера", 130), ("state", "Состояние", 90), ("res", "Разрешение", 90),
            ("codec", "Кодек", 60), ("fps", "FPS", 50), ("frames", "Кадров", 70),
            ("recon", "Разрывов", 70), ("uptime", "Аптайм", 70), ("idle", "Нет кадров", 80),
            ("motion", "Движение", 70), ("events", "События", 60), ("error", "Последняя ошибка", 260)]

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Анализ потоков")
        self.geometry("1100x380")
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Button(bar, text="Диагностика выбранной", command=self.diag_selected).pack(side="left")
        ttk.Button(bar, text="Диагностика всех", command=app.diagnose_all).pack(side="left", padx=6)
        ttk.Button(bar, text="Экспорт CSV", command=self.export).pack(side="left")
        self.tree = ttk.Treeview(self, columns=[c[0] for c in self.COLS], show="headings")
        for key, text, w in self.COLS:
            self.tree.heading(key, text=text)
            self.tree.column(key, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)
        self.refresh()

    def refresh(self):
        if not self.winfo_exists():
            return
        now = time.time()
        names = {"online": "онлайн", "connecting": "подключение", "offline": "нет связи"}
        ids = [c["id"] for c in self.app.cfg["cameras"]]
        for iid in self.tree.get_children():
            if iid not in ids:
                self.tree.delete(iid)
        for cam in self.app.cfg["cameras"]:
            wk = self.app.workers.get(cam["id"])
            if wk is None:
                vals = (cam["name"], "выключена") + ("—",) * 10
            else:
                on = wk.state == "online"
                vals = (cam["name"], names[wk.state],
                        f"{wk.size[0]}x{wk.size[1]}" if wk.size[0] else "—", wk.codec or "—",
                        f"{wk.fps:.1f}", wk.frames, wk.reconnects,
                        fmt_time(now - wk.connected_at) if on and wk.connected_at else "—",
                        f"{now - wk.last_frame_at:.1f} с" if on and wk.last_frame_at else "—",
                        f"{wk.motion:.1f}%", wk.events, wk.last_error[:80])
            if self.tree.exists(cam["id"]):
                self.tree.item(cam["id"], values=vals)
            else:
                self.tree.insert("", "end", iid=cam["id"], values=vals)
        self.after(1000, self.refresh)

    def diag_selected(self):
        sel = self.tree.selection()
        if sel:
            self.app.diagnose(sel[0])

    def export(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".csv",
                                            initialfile=f"analysis_{datetime.now():%Y%m%d_%H%M%S}.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow([c[1] for c in self.COLS])
            for iid in self.tree.get_children():
                w.writerow(self.tree.item(iid, "values"))
        self.app.log(f"Анализ сохранён: {path}")


class SettingsDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Настройки")
        self.resizable(False, False)
        self.transient(app)
        s = app.settings
        self.v = {
            "netmask": tk.StringVar(value=s["netmask"]), "gateway": tk.StringVar(value=s["gateway"]),
            "motion": tk.BooleanVar(value=s["motion"]), "motion_threshold": tk.StringVar(value=str(s["motion_threshold"])),
            "save_events": tk.BooleanVar(value=s["save_events"]), "segment_min": tk.StringVar(value=str(s["segment_min"])),
            "tour_sec": tk.StringVar(value=str(s["tour_sec"])),
            "record_mode": tk.StringVar(value=s.get("record_mode", "motion")),
            "motion_pre_sec": tk.StringVar(value=str(s.get("motion_pre_sec", 5))),
            "motion_post_sec": tk.StringVar(value=str(s.get("motion_post_sec", 10))),
            "record_copy": tk.BooleanVar(value=s.get("record_copy", True)),
            "hwaccel": tk.StringVar(value=s.get("hwaccel", "none")),
            "ui_theme": tk.StringVar(value=s.get("ui_theme", "guard")),
        }
        f = ttk.Frame(self, padding=12)
        f.pack()
        rows = [("Маска сети (для диагностики)", "netmask"), ("Шлюз (для диагностики)", "gateway"),
                ("Порог движения, % кадра", "motion_threshold"), ("Длина файла записи, мин", "segment_min"),
                ("Смена страниц в «Туре», сек", "tour_sec"),
                ("Буфер «до события», сек", "motion_pre_sec"),
                ("Писать ещё после движения, сек", "motion_post_sec")]
        for i, (label, key) in enumerate(rows):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="w", pady=3)
            ttk.Entry(f, textvariable=self.v[key], width=18).grid(row=i, column=1, pady=3, padx=(8, 0))
        r = len(rows)
        ttk.Checkbutton(f, text="Детектор движения", variable=self.v["motion"]).grid(
            row=r, column=0, columnspan=2, sticky="w"); r += 1
        ttk.Checkbutton(f, text="Сохранять снимок при движении (папка events)",
                        variable=self.v["save_events"]).grid(row=r, column=0, columnspan=2, sticky="w"); r += 1
        ttk.Checkbutton(f, text="Запись без перекодирования (ffmpeg -c copy), если ffmpeg найден",
                        variable=self.v["record_copy"]).grid(row=r, column=0, columnspan=2, sticky="w"); r += 1

        ttk.Label(f, text="Режим записи камер по умолчанию").grid(row=r, column=0, sticky="w", pady=(6, 3))
        ttk.Combobox(f, textvariable=self.v["record_mode"], width=16, state="readonly",
                     values=["always", "motion", "off"]).grid(row=r, column=1, sticky="w", pady=(6, 3)); r += 1
        ttk.Label(f, text="(always — всегда, motion — только по движению, off — выключено;"
                          "\nу каждой камеры можно задать свой режим в её настройках)",
                  foreground="#888", justify="left").grid(row=r, column=0, columnspan=2, sticky="w"); r += 1

        ttk.Label(f, text="Аппаратное декодирование").grid(row=r, column=0, sticky="w", pady=(6, 3))
        ttk.Combobox(f, textvariable=self.v["hwaccel"], width=16, state="readonly",
                     values=["none", "cuda", "dxva2", "d3d11va", "qsv"]).grid(row=r, column=1, sticky="w", pady=(6, 3)); r += 1
        ttk.Label(f, text="(нужен ffmpeg; меняется только для новых подключений — сделайте «Переподключить»)",
                  foreground="#888", justify="left").grid(row=r, column=0, columnspan=2, sticky="w"); r += 1

        ttk.Label(f, text="Оформление").grid(row=r, column=0, sticky="w", pady=(6, 3))
        ttk.Combobox(f, textvariable=self.v["ui_theme"], width=16, state="readonly",
                     values=["guard", "neon", "classic"]).grid(row=r, column=1, sticky="w", pady=(6, 3)); r += 1
        ttk.Label(f, text="(guard — графит/сталь с красным для тревог (по умолчанию);"
                          "\nneon — прежняя неоновая тема; classic — светлая)",
                  foreground="#888", justify="left").grid(row=r, column=0, columnspan=2, sticky="w"); r += 1

        bb = ttk.Frame(f)
        bb.grid(row=r, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(bb, text="Сохранить", command=self.ok).pack(side="left", padx=4)
        ttk.Button(bb, text="Отмена", command=self.destroy).pack(side="left")
        self.grab_set()

    def ok(self):
        v = self.v
        try:
            vals = {"netmask": v["netmask"].get().strip(), "gateway": v["gateway"].get().strip(),
                    "motion": v["motion"].get(), "save_events": v["save_events"].get(),
                    "motion_threshold": float(v["motion_threshold"].get().replace(",", ".")),
                    "segment_min": max(1, int(v["segment_min"].get())),
                    "tour_sec": max(2, int(v["tour_sec"].get())),
                    "record_mode": v["record_mode"].get(),
                    "motion_pre_sec": max(0, int(v["motion_pre_sec"].get())),
                    "motion_post_sec": max(0, int(v["motion_post_sec"].get())),
                    "record_copy": v["record_copy"].get(),
                    "hwaccel": v["hwaccel"].get(),
                    "ui_theme": v["ui_theme"].get()}
        except ValueError:
            messagebox.showwarning("Настройки", "Проверьте числовые значения", parent=self)
            return
        theme_changed = vals["ui_theme"] != self.app.settings.get("ui_theme", "guard")
        hwaccel_changed = vals["hwaccel"] != self.app.settings.get("hwaccel", "none")
        self.app.settings.update(vals)
        apply_ffmpeg_options(self.app.settings)
        save_config(self.app.cfg)
        if theme_changed:
            self.app.apply_theme()
        if hwaccel_changed:
            messagebox.showinfo("Настройки", "Аппаратное декодирование применится к камерам после "
                                              "их переподключения (правый клик → «Переподключить»).", parent=self)
        self.destroy()


# ======================================================================
#  Неоновая тема
# ======================================================================
NEON = {
    "bg": "#070b12", "panel": "#0c121c", "panel2": "#101826",
    "cyan": "#00f0ff", "magenta": "#ff2bd6", "green": "#39ff9e",
    "amber": "#ffb000", "red": "#ff4d6d", "text": "#d7f3ff", "dim": "#5c7a8a",
    "accent": "#00f0ff", "accent2": "#ff2bd6",
}
# Графитово-антрацитовая тема охранного образца: стальные акценты для
# обычного состояния, приглушённый красный — только для тревог/риска
# (тот же оттенок, что risk.level_color("высокий"), чтобы цвет "опасно"
# был одинаковым и в таблице риска, и в общем оформлении).
GUARD = {
    "bg": "#11151b", "panel": "#181e26", "panel2": "#212a34",
    "accent": "#8fa3b8", "accent2": "#c0392b", "green": "#3ddc84",
    "amber": "#e8a33d", "red": "#c0392b", "text": "#e7ecf1", "dim": "#60707f",
}
THEMES = {"neon": NEON, "guard": GUARD}
CLASSIC_TILE_BG = "#111111"


def apply_enhance(img, enh):
    """Улучшение картинки для показа: авто (CLAHE) либо яркость/контраст + резкость/шумодав."""
    if not enh or img is None:
        return img
    out = img
    if enh.get("auto"):
        lab = cv2.cvtColor(out, cv2.COLOR_BGR2LAB)
        l, a, b = cv2.split(lab)
        l = cv2.createCLAHE(clipLimit=2.2, tileGridSize=(8, 8)).apply(l)
        out = cv2.cvtColor(cv2.merge((l, a, b)), cv2.COLOR_LAB2BGR)
    else:
        br, ct = enh.get("brightness", 0), enh.get("contrast", 1.0)
        if br or abs(ct - 1.0) > 1e-3:
            out = cv2.convertScaleAbs(out, alpha=ct, beta=br)
    if enh.get("denoise"):
        out = cv2.bilateralFilter(out, 5, 45, 45)
    if enh.get("sharpen"):
        blur = cv2.GaussianBlur(out, (0, 0), 2.5)
        out = cv2.addWeighted(out, 1.5, blur, -0.5, 0)
    return out


def crop_zoom(frame, zoom, cx, cy):
    """Возвращает кроп кадра под цифровой зум вокруг точки (cx,cy) в долях [0..1]."""
    if zoom <= 1.001:
        return frame
    h, w = frame.shape[:2]
    cw, ch = w / zoom, h / zoom
    x0 = min(max(0.0, cx * w - cw / 2), max(0.0, w - cw))
    y0 = min(max(0.0, cy * h - ch / 2), max(0.0, h - ch))
    return frame[int(y0):int(y0 + ch), int(x0):int(x0 + cw)]


# ======================================================================
#  Диалог улучшения изображения
# ======================================================================
class EnhanceDialog(tk.Toplevel):
    def __init__(self, app, cid):
        super().__init__(app)
        self.app, self.cid = app, cid
        cam = app.cam_by_id(cid)
        self.title(f"Улучшение изображения — {cam['name']}")
        self.resizable(False, False)
        self.transient(app)
        e = dict(cam.get("enhance") or {})
        self.v = {
            "auto": tk.BooleanVar(value=e.get("auto", False)),
            "brightness": tk.IntVar(value=int(e.get("brightness", 0))),
            "contrast": tk.DoubleVar(value=float(e.get("contrast", 1.0))),
            "sharpen": tk.BooleanVar(value=e.get("sharpen", False)),
            "denoise": tk.BooleanVar(value=e.get("denoise", False)),
        }
        f = ttk.Frame(self, padding=12)
        f.pack()
        ttk.Checkbutton(f, text="Авто-коррекция (CLAHE, рекомендуется для тёмных камер)",
                         variable=self.v["auto"], command=self._toggle_auto).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))
        ttk.Label(f, text="Яркость").grid(row=1, column=0, sticky="w")
        self.s_b = ttk.Scale(f, from_=-100, to=100, variable=self.v["brightness"],
                              command=lambda _=None: self.preview(), length=220)
        self.s_b.grid(row=1, column=1, sticky="ew", padx=6)
        ttk.Label(f, text="Контраст").grid(row=2, column=0, sticky="w")
        self.s_c = ttk.Scale(f, from_=0.5, to=2.0, variable=self.v["contrast"],
                              command=lambda _=None: self.preview(), length=220)
        self.s_c.grid(row=2, column=1, sticky="ew", padx=6)
        ttk.Checkbutton(f, text="Резкость", variable=self.v["sharpen"],
                         command=self.preview).grid(row=3, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(f, text="Шумодав (для картинки в темноте)", variable=self.v["denoise"],
                         command=self.preview).grid(row=4, column=0, columnspan=2, sticky="w")
        bb = ttk.Frame(f)
        bb.grid(row=5, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(bb, text="Сбросить", command=self.reset).pack(side="left", padx=4)
        ttk.Button(bb, text="Закрыть", command=self.destroy).pack(side="left")
        self._toggle_auto()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _toggle_auto(self):
        state = "disabled" if self.v["auto"].get() else "normal"
        self.s_b.config(state=state)
        self.s_c.config(state=state)
        self.preview()

    def _enh(self):
        return {"auto": self.v["auto"].get(), "brightness": self.v["brightness"].get(),
                "contrast": round(self.v["contrast"].get(), 2), "sharpen": self.v["sharpen"].get(),
                "denoise": self.v["denoise"].get()}

    def preview(self, _=None):
        cam = self.app.cam_by_id(self.cid)
        if cam:
            cam["enhance"] = self._enh()   # применяется сразу (без реконнекта камеры)

    def reset(self):
        self.v["auto"].set(False)
        self.v["brightness"].set(0)
        self.v["contrast"].set(1.0)
        self.v["sharpen"].set(False)
        self.v["denoise"].set(False)
        self._toggle_auto()

    def destroy(self):
        self.preview()
        save_config(self.app.cfg)
        super().destroy()


# ======================================================================
#  Главное окно
# ======================================================================
class Tile:
    def __init__(self, label, overlay, cam_id):
        self.label, self.overlay, self.cam_id = label, overlay, cam_id
        self.key, self.photo = None, None


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetSuite — просмотр камер и сканер сети")
        # iconbitmap(default=...) выставляет иконку сразу для главного окна
        # и для всех Toplevel, создаваемых позже (ScanWindow, TopologyWindow,
        # диалоги и т.п.) - не нужно дублировать вызов в каждом окне.
        # Best-effort: если .ico отсутствует или платформа не Windows
        # (например, запуск для разработки на Linux/macOS), просто не падаем.
        try:
            self.iconbitmap(default=ICON_PATH)
        except Exception:
            try:
                self.iconphoto(True, tk.PhotoImage(file=resource_path("assets", "netsuite.png")))
            except Exception:
                pass
        self.geometry("1320x780")
        self.minsize(960, 600)
        self.cfg = load_config()
        self.settings = self.cfg["settings"]
        apply_ffmpeg_options(self.settings)
        self.workers, self.tiles = {}, []
        self.page, self.pages, self.focus_id, self.fs = 0, 1, None, False
        self.ui_q, self.log_q = queue.Queue(), queue.Queue()
        self.tour = tk.BooleanVar(value=False)
        self._tour_t = time.time()
        self.view_state = {}        # cid -> {"zoom":float, "cx":float, "cy":float} — цифровой зум/пан
        self._drag_cid = None        # id камеры, которую сейчас перетаскивают (смена порядка)
        self._pan_start = None       # (x, y, view_state-копия) при панорамировании зумом
        self.sound_cid = None        # камера, у которой сейчас включён звук (одновременно только одна)
        self.style = ttk.Style(self)
        self._build_ui()
        self.apply_theme()
        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<Escape>", self.on_escape)
        self.bind("<Left>", lambda e: self.change_page(-1))
        self.bind("<Right>", lambda e: self.change_page(1))
        self.bind("f", lambda e: self.fullscreen_camera(self.focus_id) if self.focus_id else None)
        self.bind("F", lambda e: self.fullscreen_camera(self.focus_id) if self.focus_id else None)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.log("Программа запущена")
        self.sync_workers()
        self.rebuild_tiles()
        self.after(40, self.render)
        self.after(100, self.poll)
        self.after(500, self.refresh_list)

    # ---------- оформление ----------
    def apply_theme(self):
        theme = self.settings.get("ui_theme", "guard")
        pal = THEMES.get(theme)           # None => "classic" (светлая) тема
        self.pal, self.theme_name = pal, theme
        bg = pal["bg"] if pal else "#f0f0f0"
        panel = pal["panel"] if pal else "#f0f0f0"
        fg = pal["text"] if pal else "#000000"
        accent = pal["accent"] if pal else "#0078d7"
        accent2 = pal["accent2"] if pal else "#0078d7"
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.configure(bg=bg)
        self.style.configure(".", background=panel, foreground=fg, fieldbackground=panel,
                              font=("Segoe UI", 10))
        self.style.configure("TFrame", background=panel)
        self.style.configure("TLabel", background=panel, foreground=fg)
        self.style.configure("TCheckbutton", background=panel, foreground=fg)
        self.style.configure("TButton", background=pal["panel2"] if pal else panel,
                              foreground=accent if pal else fg, bordercolor=accent if pal else "#999",
                              focusthickness=1, padding=4)
        self.style.map("TButton", background=[("active", pal["panel2"] if pal else "#e0e0e0")],
                        foreground=[("active", accent2 if pal else fg)])
        self.style.configure("TCombobox", fieldbackground=pal["panel2"] if pal else "white", foreground=fg)
        self.style.configure("Treeview", background=pal["panel2"] if pal else "white",
                              fieldbackground=pal["panel2"] if pal else "white", foreground=fg, rowheight=22)
        self.style.configure("Treeview.Heading", background=panel, foreground=accent if pal else fg)
        self.style.map("Treeview", background=[("selected", accent if pal else "#0078d7")],
                        foreground=[("selected", "#000000" if pal else "white")])
        # Header / NOC-статус-бар — отдельная стилевая группа, чтобы не
        # зависеть от общего ".", даже если позже поменяют базовый стиль.
        self.style.configure("Header.TFrame", background=bg)
        self.style.configure("Header.TLabel", background=bg, foreground=fg)
        self.style.configure("HeaderTitle.TLabel", background=bg, foreground=fg,
                              font=("Segoe UI Semibold", 13))
        self.style.configure("HeaderTag.TLabel", background=bg, foreground=(accent if pal else "#0078d7"),
                              font=("Segoe UI", 9))
        self.style.configure("Status.TFrame", background=panel)
        self.style.configure("Status.TLabel", background=panel, foreground=(pal["dim"] if pal else "#666"),
                              font=("Segoe UI", 9))
        self.style.configure("StatusValue.TLabel", background=panel, foreground=fg, font=("Segoe UI", 9, "bold"))
        if hasattr(self, "grid_frame"):
            self.grid_frame.config(bg="#000000")
        if hasattr(self, "logbox"):
            self.logbox.config(bg=pal["panel2"] if pal else "white", fg=fg,
                                insertbackground=fg)
        for t in self.tiles:
            t.label.config(bg="#000000" if pal else CLASSIC_TILE_BG, fg=pal["dim"] if pal else "#8a8a8a")
        if hasattr(self, "threat_dot"):
            self.refresh_status_bar()

    # ---------- шапка и NOC-статус-бар (только внешний вид, без логики окон) ----------
    def _build_header(self):
        hdr = self.header = ttk.Frame(self, style="Header.TFrame", padding=(10, 6))
        hdr.grid(row=0, column=0, sticky="ew")
        try:
            logo_img = tk.PhotoImage(file=resource_path("assets", "netsuite.png"))
            self._logo_img = logo_img.subsample(max(1, logo_img.width() // 28))
            ttk.Label(hdr, image=self._logo_img, style="Header.TLabel").pack(side="left", padx=(0, 8))
        except Exception:
            pass
        title_box = ttk.Frame(hdr, style="Header.TFrame")
        title_box.pack(side="left")
        ttk.Label(title_box, text="NETGUARD SUITE", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(title_box, text="Видеонаблюдение и охрана периметра сети",
                  style="HeaderTag.TLabel").pack(anchor="w")

    def _build_status_bar(self):
        """NOC-подобная полоса состояния: время, число камер в сети, число
        узлов под наблюдением (из последнего скана сети) и агрегированный
        уровень угрозы сети (по последней оценке риска)."""
        sb = self.statusbar = ttk.Frame(self, style="Status.TFrame", padding=(10, 3))
        sb.grid(row=1, column=0, sticky="ew")
        self._watch = {"nodes": 0, "risk_counts": {"низкий": 0, "средний": 0, "высокий": 0}}

        def field(label):
            box = ttk.Frame(sb, style="Status.TFrame")
            box.pack(side="left", padx=(0, 22))
            ttk.Label(box, text=label, style="Status.TLabel").pack(side="left", padx=(0, 5))
            val = ttk.Label(box, text="—", style="StatusValue.TLabel")
            val.pack(side="left")
            return val

        self.clock_lbl = field("Время:")
        self.cams_lbl = field("Камеры:")
        self.nodes_lbl = field("Узлы под наблюдением:")
        threat_box = ttk.Frame(sb, style="Status.TFrame")
        threat_box.pack(side="left")
        ttk.Label(threat_box, text="Угроза сети:", style="Status.TLabel").pack(side="left", padx=(0, 5))
        self.threat_dot = tk.Label(threat_box, text="●", bg=self.cget("bg"), font=("Segoe UI", 10))
        self.threat_dot.pack(side="left", padx=(0, 3))
        self.threat_lbl = ttk.Label(threat_box, text="нет данных", style="StatusValue.TLabel")
        self.threat_lbl.pack(side="left")
        self._tick_status_clock()

    def _tick_status_clock(self):
        self.clock_lbl.config(text=f"{datetime.now():%H:%M:%S}")
        self.after(1000, self._tick_status_clock)

    def update_watch_summary(self, nodes, risk_counts):
        """Вызывается из ScanWindow при каждом обновлении списка узлов —
        отдаёт данные для статус-бара. Сами данные не меняет и не хранит
        нигде, кроме как для отображения."""
        self._watch = {"nodes": nodes, "risk_counts": dict(risk_counts)}
        self.refresh_status_bar()

    def refresh_status_bar(self):
        if not hasattr(self, "threat_dot"):
            return
        pal = getattr(self, "pal", None)
        online = sum(1 for w in self.workers.values() if getattr(w, "state", "") == "online")
        total = len(self.cfg.get("cameras", []))
        self.cams_lbl.config(text=f"{online}/{total} в сети")
        w = self._watch
        self.nodes_lbl.config(text=str(w["nodes"]) if w["nodes"] else "—")
        counts = w["risk_counts"]
        if not w["nodes"]:
            level, text = None, "нет данных"
        elif counts.get("высокий"):
            level, text = "высокий", f"высокая ({counts['высокий']})"
        elif counts.get("средний"):
            level, text = "средний", f"повышенная ({counts['средний']})"
        else:
            level, text = "низкий", "низкая"
        dot_color = {"высокий": (pal["red"] if pal else "#c0392b"),
                     "средний": (pal["amber"] if pal else "#e8a33d"),
                     "низкий": (pal["green"] if pal else "#2e7d32"),
                     None: (pal["dim"] if pal else "#888")}[level]
        bg = self.cget("bg")
        self.threat_dot.config(fg=dot_color, bg=bg)
        self.threat_lbl.config(text=text)

    # ---------- интерфейс ----------
    def _build_ui(self):
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._build_header()
        self._build_status_bar()

        tb = self.toolbar = ttk.Frame(self, padding=(6, 4))
        tb.grid(row=2, column=0, sticky="ew")

        def btn(text, cmd):
            b = ttk.Button(tb, text=text, command=cmd)
            b.pack(side="left", padx=2)
            return b

        def sep():
            ttk.Separator(tb, orient="vertical").pack(side="left", fill="y", padx=6)

        btn("＋ Камера", self.add_camera)
        btn("Поиск в сети", self.open_scan)
        btn("Анализ", self.open_analysis)
        btn("Диагностика всех", self.diagnose_all)
        btn("Настройки", self.open_settings)
        sep()
        ttk.Label(tb, text="Раскладка:").pack(side="left")
        self.layout_var = tk.StringVar(value=self.cfg.get("layout", "Авто"))
        cb = ttk.Combobox(tb, textvariable=self.layout_var, values=LAYOUTS, state="readonly", width=6)
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", self.on_layout)
        btn("◀", lambda: self.change_page(-1))
        self.page_var = tk.StringVar(value="1/1")
        ttk.Label(tb, textvariable=self.page_var, width=5, anchor="center").pack(side="left")
        btn("▶", lambda: self.change_page(1))
        ttk.Checkbutton(tb, text="Тур", variable=self.tour).pack(side="left", padx=6)
        sep()
        btn("Снимок всех", self.snapshot_all)
        self.rec_btn = btn("● Запись", self.toggle_record_all)
        btn("Весь экран (F11)", self.toggle_fullscreen)
        btn("Камера на весь экран (F)", lambda: self.fullscreen_camera(self.focus_id or self.selected_id()))

        body = ttk.Frame(self)
        body.grid(row=3, column=0, sticky="nsew")
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        side = self.side = ttk.Frame(body, width=270)
        side.grid(row=0, column=0, sticky="ns")
        side.grid_propagate(False)
        self.tree = ttk.Treeview(side, columns=("name", "state"), show="headings", selectmode="browse")
        self.tree.heading("name", text="Камера")
        self.tree.heading("state", text="Состояние")
        self.tree.column("name", width=140)
        self.tree.column("state", width=110)
        for tag, color in (("online", GUARD["green"]), ("connecting", GUARD["amber"]),
                           ("offline", GUARD["red"]), ("off", GUARD["dim"])):
            self.tree.tag_configure(tag, foreground=color)
        self.tree.pack(fill="both", expand=True, padx=(4, 0), pady=4)
        self.tree.bind("<Double-1>", lambda e: self.toggle_focus(self.tree.identify_row(e.y) or None))
        self.tree.bind("<Button-3>", self.on_tree_menu)
        bf = ttk.Frame(side)
        bf.pack(fill="x", padx=4, pady=(0, 4))
        ttk.Button(bf, text="Изменить", command=lambda: self.sel_do(self.edit_camera)).pack(side="left")
        ttk.Button(bf, text="Удалить", command=lambda: self.sel_do(self.delete_camera)).pack(side="left", padx=4)

        self.grid_frame = tk.Frame(body, bg="#000000")
        self.grid_frame.grid(row=0, column=1, sticky="nsew")

        lf = self.logframe = ttk.Frame(self)
        lf.grid(row=4, column=0, sticky="ew")
        self.logbox = tk.Text(lf, height=6, state="disabled", wrap="none", font=("Consolas", 9))
        sb = ttk.Scrollbar(lf, command=self.logbox.yview)
        self.logbox.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.logbox.pack(fill="x")

    # ---------- служебное ----------
    def log(self, msg):
        self.log_q.put(f"{datetime.now():%H:%M:%S}  {msg}")

    def run_bg(self, func, done=None):
        def target():
            try:
                res = func()
            except Exception as e:
                res = e
            if done:
                self.ui_q.put((done, res))
        threading.Thread(target=target, daemon=True).start()

    def poll(self):
        try:
            while True:
                cb, res = self.ui_q.get_nowait()
                try:
                    cb(res)
                except tk.TclError:
                    pass
                except Exception as e:
                    self.log(f"Ошибка интерфейса: {e}")
        except queue.Empty:
            pass
        lines = []
        try:
            while True:
                lines.append(self.log_q.get_nowait())
        except queue.Empty:
            pass
        if lines:
            self.logbox.config(state="normal")
            self.logbox.insert("end", "\n".join(lines) + "\n")
            count = int(self.logbox.index("end-1c").split(".")[0])
            if count > 500:
                self.logbox.delete("1.0", f"{count - 500}.0")
            self.logbox.see("end")
            self.logbox.config(state="disabled")
            try:
                if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 2_000_000:
                    os.replace(LOG_PATH, LOG_PATH + ".old")
                with open(LOG_PATH, "a", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
            except OSError:
                pass
        self.after(100, self.poll)

    # поля, при изменении которых камеру нужно переподключать; остальное (звук,
    # режим записи, улучшение картинки) применяется «на лету» без разрыва потока
    _RECONNECT_KEYS = ("ip", "port", "user", "password", "path", "path_sub")

    def sync_workers(self):
        want = {c["id"]: c for c in self.cfg["cameras"] if c.get("enabled", True)}
        for cid in list(self.workers):
            wk = self.workers[cid]
            if cid not in want:
                self.workers.pop(cid).stop()
                continue
            cam = want[cid]
            if any(wk.cam.get(k) != cam.get(k) for k in self._RECONNECT_KEYS):
                self.workers.pop(cid).stop()
                continue
            wk.cam = dict(cam)           # обновляем «мягкие» поля без реконнекта
            wk.has_sub = bool(cam.get("path_sub"))
            wk.set_sound(bool(cam.get("sound", False)))
        for cid, cam in want.items():
            if cid not in self.workers:
                wk = CameraWorker(cam, self.settings, self.log, report_path_found=self._report_path_found)
                wk.start()
                self.workers[cid] = wk

    def cam_by_id(self, cid):
        return next((c for c in self.cfg["cameras"] if c["id"] == cid), None)

    def after_change(self):
        save_config(self.cfg)
        self.sync_workers()
        self.sync_focus()
        self.rebuild_tiles()
        self._update_list()

    # ---------- список камер ----------
    def _update_list(self):
        cams = self.cfg["cameras"]
        ids = [c["id"] for c in cams]
        for iid in self.tree.get_children():
            if iid not in ids:
                self.tree.delete(iid)
        texts = {"online": "● {fps:.0f} fps", "connecting": "◌ подключение", "offline": "○ нет связи"}
        for cam in cams:
            wk = self.workers.get(cam["id"])
            if wk is None:
                state, tag = "выключена", "off"
            else:
                state, tag = texts[wk.state].format(fps=wk.fps), wk.state
                if wk.record:
                    state += "  ● REC"
            vals = (cam["name"], state)
            if self.tree.exists(cam["id"]):
                self.tree.item(cam["id"], values=vals, tags=(tag,))
            else:
                self.tree.insert("", "end", iid=cam["id"], values=vals, tags=(tag,))
        rec = any(w.record for w in self.workers.values())
        self.rec_btn.config(text="■ Стоп запись" if rec else "● Запись")

    def refresh_list(self):
        self._update_list()
        self.refresh_status_bar()
        self.after(1000, self.refresh_list)

    def selected_id(self):
        sel = self.tree.selection()
        return sel[0] if sel else None

    def sel_do(self, func):
        cid = self.selected_id()
        if cid:
            func(cid)

    def on_tree_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.cam_menu(event, iid)

    def cam_menu(self, event, cid):
        if not cid:
            return
        wk = self.workers.get(cid)
        cam = self.cam_by_id(cid)
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Развернуть / свернуть", command=lambda: self.toggle_focus(cid))
        m.add_command(label="На весь экран (F)", command=lambda: self.fullscreen_camera(cid))
        m.add_command(label="Снимок", command=lambda: self.snapshot(cid))
        m.add_command(label="Остановить запись" if wk and wk.manual_record else "Начать запись (вручную)",
                      command=lambda: self.toggle_record(cid))
        m.add_command(label="Выключить звук" if self.sound_cid == cid else "Включить звук",
                      command=lambda: self.toggle_sound(cid))
        m.add_command(label="Сбросить зум", command=lambda: self.view_state.pop(cid, None))
        m.add_command(label="Улучшение изображения…", command=lambda: EnhanceDialog(self, cid))
        m.add_command(label="Переподключить", command=lambda: self.reconnect(cid))
        m.add_separator()
        m.add_command(label="Изменить…", command=lambda: self.edit_camera(cid))
        m.add_command(label="Диагностика…", command=lambda: self.diagnose(cid))
        m.tk_popup(event.x_root, event.y_root)

    def toggle_sound(self, cid):
        if self.sound_cid and self.sound_cid != cid:
            old = self.workers.get(self.sound_cid)
            if old:
                old.set_sound(False)
        turn_on = self.sound_cid != cid
        self.sound_cid = cid if turn_on else None
        wk = self.workers.get(cid)
        if wk:
            wk.set_sound(turn_on)
        self.log(f"[{(self.cam_by_id(cid) or {}).get('name', cid)}] звук {'включён' if turn_on else 'выключен'}")

    # ---------- камеры ----------
    def add_camera(self, prefill=None):
        cam = new_camera(name=f"Камера {len(self.cfg['cameras']) + 1}", **(prefill or {}))
        dlg = CameraDialog(self, cam)
        self.wait_window(dlg)
        if dlg.result:
            self.cfg["cameras"].append(dlg.result)
            self.after_change()

    def edit_camera(self, cid):
        cam = self.cam_by_id(cid)
        if not cam:
            return
        dlg = CameraDialog(self, cam)
        self.wait_window(dlg)
        if dlg.result:
            self.cfg["cameras"][self.cfg["cameras"].index(cam)] = dlg.result
            self.after_change()

    def delete_camera(self, cid):
        cam = self.cam_by_id(cid)
        if cam and messagebox.askyesno("Удаление", f"Удалить камеру «{cam['name']}»?", parent=self):
            self.cfg["cameras"].remove(cam)
            if self.focus_id == cid:
                self.focus_id = None
            self.after_change()

    def reconnect(self, cid):
        wk = self.workers.pop(cid, None)
        if wk:
            wk.stop()
        self.sync_workers()
        self.sync_focus()
        self.rebuild_tiles()

    def _report_path_found(self, cid, is_sub, path):
        """Вызывается из потока CameraWorker (см. CameraWorker._try_autofind_path) —
        безопасно переносим сохранение в основной поток через ui_q."""
        self.ui_q.put((self._apply_found_path, (cid, is_sub, path)))

    def _apply_found_path(self, args):
        cid, is_sub, path = args
        cam = self.cam_by_id(cid)
        if not cam:
            return
        key = "path_sub" if is_sub else "path"
        if cam.get(key) != path:
            cam[key] = path
            save_config(self.cfg)
            self.log(f"[{cam['name']}] автоподбор: путь сохранён в конфигурацию ({path})")

    # ---------- раскладка ----------
    def on_layout(self, _=None):
        self.cfg["layout"] = self.layout_var.get()
        self.page, self.focus_id = 0, None
        save_config(self.cfg)
        self.rebuild_tiles()

    def change_page(self, d):
        if self.focus_id or self.pages < 2:
            return
        self.page = (self.page + d) % self.pages
        self._tour_t = time.time()
        self.rebuild_tiles()

    def toggle_focus(self, cid):
        if not cid:
            return
        if self.focus_id == cid:
            self.focus_id = None
            self.view_state.pop(cid, None)
        else:
            self.focus_id = cid
        self.sync_focus()
        self.rebuild_tiles()

    def sync_focus(self):
        """Говорит воркерам, какая камера сейчас в фокусе — для переключения на основной поток."""
        for cid, wk in self.workers.items():
            wk.set_focused(cid == self.focus_id)

    def fullscreen_camera(self, cid):
        """Полноэкранный режим одной камеры: фокус + скрытие всех панелей."""
        if not cid:
            return
        if self.focus_id != cid:
            self.focus_id = cid
            self.sync_focus()
            self.rebuild_tiles()
        if not self.fs:
            self.toggle_fullscreen()

    def on_escape(self, _=None):
        if self.fs:
            self.toggle_fullscreen()
        elif self.focus_id:
            self.toggle_focus(self.focus_id)

    def toggle_fullscreen(self, _=None):
        """F11 или повторное нажатие — включает/выключает настоящий полноэкранный
        режим (поверх панели задач Windows). Esc тоже выходит — см. on_escape."""
        self.fs = not self.fs
        if self.fs:
            try:
                self._pre_fs_geometry = self.geometry()
            except tk.TclError:
                self._pre_fs_geometry = None
            self.attributes("-fullscreen", True)
        else:
            self.attributes("-fullscreen", False)
            geo = getattr(self, "_pre_fs_geometry", None)
            if geo:
                self.after(10, lambda: self.geometry(geo))
        for w in (self.header, self.statusbar, self.toolbar, self.side, self.logframe):
            w.grid_remove() if self.fs else w.grid()
        # Страховка от артефактов Windows при включённом fullscreen сразу после
        # смены разрешения/монитора: переустановка атрибута гарантированно
        # пересчитывает геометрию под актуальный экран.
        self.after(60, self._reassert_fullscreen_geometry)

    def _reassert_fullscreen_geometry(self):
        if self.fs:
            self.attributes("-fullscreen", False)
            self.attributes("-fullscreen", True)
            self.focus_force()

    def rebuild_tiles(self):
        for t in self.tiles:
            t.label.destroy()
        self.tiles = []
        cams = [c for c in self.cfg["cameras"] if c.get("enabled", True)]
        if self.focus_id and any(c["id"] == self.focus_id for c in cams):
            shown = [c for c in cams if c["id"] == self.focus_id]
            cells, gw, gh = layout_cells("1x1", 1)
            self.pages = 1
        else:
            self.focus_id = None
            cells, gw, gh = layout_cells(self.layout_var.get(), len(cams))
            self.pages = max(1, math.ceil(len(cams) / len(cells)))
            self.page = min(self.page, self.pages - 1)
            shown = cams[self.page * len(cells):(self.page + 1) * len(cells)]
        pal = getattr(self, "pal", None)
        for i, (x, y, w, h) in enumerate(cells):
            cid = shown[i]["id"] if i < len(shown) else None
            lbl = tk.Label(self.grid_frame, bg="#000000", fg=(pal["dim"] if pal else "#8a8a8a"),
                           bd=0, font=("Segoe UI", 11),
                           highlightthickness=2, highlightbackground=(pal["panel2"] if pal else "#222222"))
            lbl.place(relx=x / gw, rely=y / gh, relwidth=w / gw, relheight=h / gh)
            ov = tk.Label(lbl, bg="#000000", fg=(pal["green"] if pal else "#2e7d32"), font=("Segoe UI", 9), padx=4)
            for widget in (lbl, ov):
                widget.bind("<Double-Button-1>", lambda e, c=cid: self.toggle_focus(c))
                widget.bind("<Button-3>", lambda e, c=cid: self.cam_menu(e, c))
            lbl.bind("<ButtonPress-1>", lambda e, c=cid: self.on_tile_press(e, c))
            lbl.bind("<B1-Motion>", lambda e, c=cid: self.on_tile_motion(e, c))
            lbl.bind("<ButtonRelease-1>", lambda e, c=cid: self.on_tile_release(e, c))
            lbl.bind("<MouseWheel>", lambda e, c=cid: self.on_tile_wheel(e, c))
            lbl.bind("<Button-4>", lambda e, c=cid: self.on_tile_wheel(e, c))
            lbl.bind("<Button-5>", lambda e, c=cid: self.on_tile_wheel(e, c))
            self.tiles.append(Tile(lbl, ov, cid))
        self.page_var.set(f"{self.page + 1}/{self.pages}")

    # ---------- перетаскивание плиток (смена порядка камер) ----------
    def on_tile_press(self, e, cid):
        if not cid:
            return
        vs = self.view_state.get(cid)
        if self.focus_id == cid and vs and vs.get("zoom", 1.0) > 1.01:
            self._pan_start = (e.x, e.y, dict(vs))
        elif not self.focus_id:
            self._drag_cid = cid

    def on_tile_motion(self, e, cid):
        if not (self._pan_start and self.focus_id == cid):
            return
        x0, y0, vs0 = self._pan_start
        tile = next((t for t in self.tiles if t.cam_id == cid), None)
        if not tile:
            return
        tw, th = max(1, tile.label.winfo_width()), max(1, tile.label.winfo_height())
        dx, dy = (x0 - e.x) / tw, (y0 - e.y) / th
        vs = self.view_state.setdefault(cid, dict(vs0))
        vs["cx"] = min(1.0, max(0.0, vs0["cx"] + dx / vs0["zoom"]))
        vs["cy"] = min(1.0, max(0.0, vs0["cy"] + dy / vs0["zoom"]))

    def on_tile_release(self, e, cid):
        if self._pan_start:
            self._pan_start = None
            return
        src, self._drag_cid = self._drag_cid, None
        if src and cid and src != cid:
            self.reorder_camera(src, cid)

    def on_tile_wheel(self, e, cid):
        if not cid or self.focus_id != cid:
            return
        up = getattr(e, "delta", 0) > 0 or getattr(e, "num", 0) == 4
        vs = self.view_state.setdefault(cid, {"zoom": 1.0, "cx": 0.5, "cy": 0.5})
        vs["zoom"] = min(6.0, max(1.0, vs["zoom"] * (1.15 if up else 1 / 1.15)))

    def reorder_camera(self, src_cid, dst_cid):
        cams = self.cfg["cameras"]
        try:
            i = next(idx for idx, c in enumerate(cams) if c["id"] == src_cid)
            j = next(idx for idx, c in enumerate(cams) if c["id"] == dst_cid)
        except StopIteration:
            return
        cams[i], cams[j] = cams[j], cams[i]
        save_config(self.cfg)
        self.rebuild_tiles()
        self._update_list()
        self.log("Порядок камер изменён (перетаскивание)")

    # ---------- отрисовка ----------
    def render(self):
        try:
            self.draw_tiles()
            if (self.tour.get() and not self.focus_id and self.pages > 1 and
                    time.time() - self._tour_t >= float(self.settings.get("tour_sec", 10))):
                self.change_page(1)
        except Exception as e:
            self.log(f"Ошибка отрисовки: {e}")
        finally:
            self.after(33 if len(self.tiles) <= 4 else 66, self.render)

    def draw_tiles(self):
        pal = getattr(self, "pal", None)
        colors = {"online": pal["green"] if pal else "#33dd77",
                  "connecting": pal["amber"] if pal else "#ffb000",
                  "offline": pal["red"] if pal else "#ff5555"}
        border_motion = pal["accent2"] if pal else "#dd3333"
        border_idle = pal["accent"] if pal else "#222222"
        for t in self.tiles:
            tw, th = t.label.winfo_width(), t.label.winfo_height()
            if tw < 40 or th < 30:
                continue
            wk = self.workers.get(t.cam_id) if t.cam_id else None
            if wk is None:
                key = ("none", t.cam_id, tw, th)
                if key != t.key:
                    t.key, t.photo = key, None
                    t.label.config(image="", text="" if t.cam_id is None else "Камера выключена")
                    t.overlay.place_forget()
                continue
            wk.target_w = min(max(tw, 320), 1920)
            cam = self.cam_by_id(t.cam_id) or wk.cam
            enh = cam.get("enhance") or {}
            focused = (self.focus_id == t.cam_id)
            vs = self.view_state.get(t.cam_id) if focused else None
            zoom = vs["zoom"] if vs else 1.0
            enh_sig = (enh.get("auto"), enh.get("brightness"), enh.get("contrast"),
                       enh.get("sharpen"), enh.get("denoise"))
            zoom_sig = (round(zoom, 2), round(vs["cx"], 3), round(vs["cy"], 3)) if vs else None
            key = (wk.frame_id, wk.state, wk.status, wk.record, wk.record_kind, wk.motion_active,
                   tw, th, int(wk.fps), enh_sig, zoom_sig, self.sound_cid == t.cam_id)
            if key == t.key:
                continue
            t.key = key
            with wk.lock:
                disp, full = wk.disp, wk.full
            name = cam.get("name", wk.cam["name"])
            if disp is not None and wk.state == "online":
                # зум — кропаем из полнокадрового изображения, если он есть и камера в фокусе
                src = disp
                if focused and zoom > 1.001 and full is not None:
                    src = crop_zoom(full, zoom, vs["cx"], vs["cy"])
                h0, w0 = src.shape[:2]
                s = min(tw / w0, th / h0)
                img = cv2.resize(src, (max(1, int(w0 * s)), max(1, int(h0 * s))),
                                 interpolation=cv2.INTER_AREA if s < 1 else cv2.INTER_LINEAR)
                if enh.get("auto") or enh.get("sharpen") or enh.get("denoise") or \
                        enh.get("brightness") or abs(enh.get("contrast", 1.0) - 1.0) > 1e-3:
                    img = apply_enhance(img, enh)
                t.photo = ImageTk.PhotoImage(Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB)))
                t.label.config(image=t.photo, text="")
            else:
                t.photo = None
                t.label.config(image="", text=f"{name}\n\n{wk.status}", wraplength=max(100, tw - 30))
            t.label.config(highlightbackground=border_motion if wk.motion_active else border_idle)
            text = f"{name}"
            if wk.state == "online":
                text += f"   {wk.fps:.0f} fps   {wk.size[0]}x{wk.size[1]}"
                if wk.use_sub:
                    text += "  [суб]"
            if focused and zoom > 1.001:
                text += f"   🔍{zoom:.1f}x"
            if wk.record:
                text += "   ● REC" + ("·copy" if wk.record_kind == "copy" else "")
            if self.sound_cid == t.cam_id:
                text += "   🔊"
            if wk.motion_active:
                text += "   ДВИЖЕНИЕ"
            t.overlay.config(text=text, fg=colors[wk.state])
            t.overlay.place(x=4, y=4)

    # ---------- действия ----------
    def snapshot(self, cid):
        wk, cam = self.workers.get(cid), self.cam_by_id(cid)
        frame = wk.full if wk else None
        if frame is None:
            self.log(f"Снимок: у «{cam['name'] if cam else cid}» нет кадра")
            return
        path = os.path.join(SNAP_DIR, f"{safe_name(cam)}_{datetime.now():%Y%m%d_%H%M%S}.jpg")
        try:
            save_jpg(path, frame)
            self.log(f"Снимок сохранён: {path}")
        except OSError as e:
            self.log(f"Не удалось сохранить снимок: {e}")

    def snapshot_all(self):
        for cid in list(self.workers):
            self.snapshot(cid)

    def toggle_record(self, cid):
        wk = self.workers.get(cid)
        if wk:
            wk.manual_record = not wk.manual_record
            mode = effective_record_mode(wk.cam, self.settings)
            extra = f" (режим камеры «{mode}» тоже может писать)" if mode != "off" else ""
            self.log(f"[{wk.cam['name']}] ручная запись {'включена' if wk.manual_record else 'выключена'}{extra}")
            self._update_list()

    def toggle_record_all(self):
        start = not any(w.manual_record for w in self.workers.values())
        for wk in self.workers.values():
            wk.manual_record = start
        self.log("Ручная запись " + ("включена для всех камер" if start else "выключена"))
        self._update_list()

    def diagnose(self, cid):
        cam = self.cam_by_id(cid)
        if cam:
            self.log(f"Диагностика «{cam['name']}»… подождите")
            self.run_bg(lambda: diagnose_camera(cam, self.settings),
                        lambda text: ReportWindow(self, f"Диагностика — {cam['name']}", self._text(text)))

    def diagnose_all(self):
        cams = list(self.cfg["cameras"])
        self.log("Диагностика всех камер… подождите")

        def work():
            return "\n\n".join(diagnose_camera(c, self.settings) for c in cams)

        self.run_bg(work, lambda text: ReportWindow(self, "Диагностика всех камер", self._text(text)))

    @staticmethod
    def _text(res):
        return f"Ошибка диагностики: {res}" if isinstance(res, Exception) else res

    def open_scan(self):
        ScanWindow(self)

    def open_analysis(self):
        AnalysisWindow(self)

    def open_settings(self):
        SettingsDialog(self)

    def on_close(self):
        save_config(self.cfg)
        workers = list(self.workers.values())
        for wk in workers:
            wk.stop()
        end = time.time() + 3
        for wk in workers:
            wk.join(max(0.0, end - time.time()))
        self.destroy()


if __name__ == "__main__":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    App().mainloop()
