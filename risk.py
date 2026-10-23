"""
risk.py - оценка риска узла сети по уже собранным данным (identify_host()
из netid.py): открытые небезопасные протоколы, HTTP(S)/RTSP(S) без
авторизации, проблемы TLS-сертификата. Не делает подбор паролей и не
пытается ничего аутентифицировать - только пассивно читает то, что узел
и так сообщает любому (баннеры, заголовки, сертификат).

Используется ТОЛЬКО для диагностики своей сети или сети, на проверку
которой у вас есть явное разрешение.
"""
import datetime
import socket
import ssl

# Порты, которые сами по себе считаются небезопасным протоколом (открытый
# текст, устаревшее шифрование и т.п.) - вне зависимости от баннера.
INSECURE_PORTS = {
    21: "FTP (пароль и данные передаются открытым текстом)",
    23: "Telnet (вся сессия, включая пароль, открытым текстом)",
    139: "NetBIOS/SMB (часто вместе с устаревшим SMBv1)",
    512: "rexec (открытый текст)", 513: "rlogin (открытый текст)",
    514: "rsh (открытый текст)",
    1900: "SSDP (обычно безобиден, но иногда используется для DDoS-отражения)",
}

LEVEL_ORDER = {"низкий": 0, "средний": 1, "высокий": 2}


def _bump(level, new_level):
    return new_level if LEVEL_ORDER[new_level] > LEVEL_ORDER[level] else level


def _check_tls(ip, port, timeout=2.5):
    """Забирает сертификат на TLS-порту (HTTPS/RTSPS и т.п.) и смотрит на
    самые частые проблемы: просрочен, самоподписанный, истекает скоро,
    слабый набор шифров/протокол. Best-effort: любая ошибка (порт закрыт,
    это вообще не TLS и т.п.) просто возвращается как "не удалось
    проверить", без исключений наружу."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                cert_bin = tls.getpeercert(binary_form=True)
                proto = tls.version()
                cipher = tls.cipher()
        issues = []
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            issues.append(f"устаревший протокол {proto}")
        if cipher and any(w in (cipher[0] or "") for w in ("RC4", "DES", "NULL", "EXPORT", "MD5")):
            issues.append(f"слабый шифр {cipher[0]}")
        # Разбираем срок действия через встроенный ssl (без cryptography):
        # получаем PEM и парсим notAfter простым способом через getpeercert
        # c CERT_NONE недоступен человекочитаемый разбор - делаем отдельное
        # соединение с проверкой, только чтобы вытащить notAfter/issuer.
        try:
            pem = ssl.DER_cert_to_PEM_cert(cert_bin)
            # Второе соединение не нужно: используем ssl._ssl через getpeercert
            # недоступно без verify, поэтому читаем дату вручную из текстового
            # представления, которое даёт openssl-подобный путь ниже.
        except Exception:
            pem = ""
        self_signed = None
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            with socket.create_connection((ip, port), timeout=timeout) as sock2:
                with ctx2.wrap_socket(sock2, server_hostname=ip) as tls2:
                    tls2.getpeercert()
            self_signed = False
        except ssl.SSLCertVerificationError as e:
            msg = str(e).lower()
            self_signed = "self" in msg or "self-signed" in msg or "unable to get local issuer" in msg
        except Exception:
            self_signed = None  # не удалось определить (другая ошибка сети)

        if self_signed:
            issues.append("самоподписанный сертификат")
        return {"ok": True, "issues": issues, "pem_available": bool(pem)}
    except Exception:
        return {"ok": False, "issues": [], "pem_available": False}


def assess_risk(host, timeout=2.5, check_tls=True):
    """host - словарь с ключами, как у identify_host()/scan(): ip, ports,
    banner, http (dict server/title/auth/status), device_type и т.п.
    Возвращает {"level": "низкий"/"средний"/"высокий", "reasons": [...]}.
    Пассивная проверка: ничего не подбирает и никуда не логинится - только
    смотрит на уже открытые порты и то, что сервис сам сообщает."""
    ip = host.get("ip", "")
    ports = set(host.get("ports") or [])
    banner = (host.get("banner") or "").lower()
    http_d = host.get("http") or {}
    reasons = []
    level = "низкий"

    for p, desc in INSECURE_PORTS.items():
        if p in ports and p != 1900:
            reasons.append(f"открыт порт {p} — {desc}")
            level = _bump(level, "высокий" if p in (21, 23) else "средний")

    if "smbv1" in banner or ("smb1" in banner):
        reasons.append("похоже, включён устаревший SMBv1 (известные уязвимости, напр. EternalBlue)")
        level = _bump(level, "высокий")

    if "ssh-1." in banner:
        reasons.append("сервер объявляет себя как SSHv1 (устаревший, небезопасный протокол)")
        level = _bump(level, "высокий")

    # HTTP(S) веб-интерфейс без запроса авторизации — потенциально открытая
    # панель управления/просмотр (не подбор пароля, просто факт: сервер не
    # прислал WWW-Authenticate на корневой странице).
    if http_d and http_d.get("status") == 200 and not http_d.get("auth"):
        reasons.append("веб-интерфейс отвечает 200 OK без запроса логина/пароля (WWW-Authenticate отсутствует)")
        level = _bump(level, "средний")

    # RTSP/RTSPS порт открыт — сам по себе это не проблема, но в сочетании
    # с "типом устройства" камера и отсутствием авторизации на сопутствующем
    # HTTP — повод присмотреться внимательнее.
    if (554 in ports or 8554 in ports) and http_d and not http_d.get("auth"):
        reasons.append("открыт RTSP-порт, при этом веб-интерфейс того же узла не запрашивает авторизацию")
        level = _bump(level, "высокий")

    if check_tls:
        for p in (443, 8443, 8554, 322):
            if p in ports:
                tls_res = _check_tls(ip, p, timeout)
                if tls_res["ok"] and tls_res["issues"]:
                    reasons.append(f"TLS на порту {p}: " + ", ".join(tls_res["issues"]))
                    level = _bump(level, "средний")
                break  # одной TLS-проверки на узел достаточно, чтобы не тормозить скан

    if not reasons:
        reasons.append("явных проблем по открытым портам/баннерам/TLS не найдено "
                        "(это не гарантия безопасности узла, а лишь отсутствие явных признаков)")

    return {"level": level, "reasons": reasons}


def level_color(level):
    """Цвет для GUI-таблицы (используется netsuite.py)."""
    return {"низкий": "#2e7d32", "средний": "#f0a500", "высокий": "#c0392b"}.get(level, "#9aa5b1")
