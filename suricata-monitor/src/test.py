import json
import os
import random
import string
import subprocess
import time
import signal
import sys
import ctypes
import sqlite3
import atexit
import threading
import winsound
import smtplib
import requests
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlparse


# Красивое название окна (заголовок консоли)
def set_window_title(title):
    """Меняет заголовок окна консоли (Windows)."""
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    except Exception:
        pass

set_window_title("Melnick | Suricata Monitor — Автоматизированный мониторинг угроз")

# ============================================================
# НАСТРОЙКИ
# ============================================================
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
    PROJECT_ROOT = BASE_DIR
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(BASE_DIR)

DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

SURICATA_EXE = r"C:\Program Files\Suricata\suricata.exe"
SURICATA_CONFIG = r"C:\Program Files\Suricata\suricata.yaml"
SURICATA_LOG_DIR = r"C:\SuricataTest\log"
SURICATA_RULES = r"C:\SuricataTest\rules\local.rules"
INTERFACE = "172.20.10.8"
CAPTURE_SECONDS = 15

EVE_FILE = os.path.join(SURICATA_LOG_DIR, "eve.json")

IP_LIST_FILE     = os.path.join(DATA_DIR, "ip_list.json")
REPORT_FILE      = os.path.join(DATA_DIR, "report.json")
CHART_FILE       = os.path.join(DATA_DIR, "suricata_chart.png")
CHART_RISK_FILE  = os.path.join(DATA_DIR, "suricata_risk_chart.png")
DB_FILE          = os.path.join(DATA_DIR, "history.db")
PENDING_FILE     = os.path.join(DATA_DIR, "pending_alerts.json")
MONITOR_LOG_FILE = os.path.join(LOGS_DIR, "monitor_log.txt")
USER_CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

# файл для авто-сгенерированных данных имитации
FAKE_GENERATED_FILE = os.path.join(DATA_DIR, "ip_list_generated.json")

DNS_THRESHOLD = 2
MALICIOUS_THRESHOLD = 2
REALTIME_CACHE_TIMEOUT = 300

VT_URL          = "https://www.virustotal.com/api/v3/ip_addresses/{}"
VT_URL_DOMAIN   = "https://www.virustotal.com/api/v3/domains/{}"
VT_URL_URL      = "https://www.virustotal.com/api/v3/urls"

active_suricata_process = None
pending_lock = threading.Lock()
USER_CONFIG = None
VT_MODE = "real"

LAST_DOMAINS = []
LAST_URLS = []

DOMAIN_CACHE = {}
URL_CACHE = {}

TRUSTED_DOMAINS = {
    "google.com", "www.google.com", "google.ru",
    "yandex.ru", "www.yandex.ru", "yandex.net", "ya.ru",
    "cloudflare.com", "github.com", "githubusercontent.com",
    "microsoft.com", "office.com", "windows.com", "windowsupdate.com",
    "msftncsi.com", "msftconnecttest.com", "live.com", "outlook.com",
    "deepseek.com", "chat.deepseek.com",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "gstatic.com", "googleapis.com", "googleusercontent.com",
    "pinterest.com", "pinimg.com",
    "oaistatic.com", "openai.com", "chatgpt.com",
    "yastatic.net", "mail.yandex.ru", "mc.yandex.ru",
    "apple.com", "icloud.com", "mozilla.org", "firefox.com",
    "wikipedia.org", "wikimedia.org", "reddit.com",
    "steampowered.com", "steamserver.net", "steamcommunity.com",
    "akamai.net", "akamaiedge.net", "edgesuite.net",
    "amazonaws.com", "cloudfront.net",
    "telegram.org", "whatsapp.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "youtube.com", "ytimg.com",
}

RANDOM_SUBDOMAINS = [
    "", "www", "api", "cdn", "mail", "static", "img", "auth",
    "login", "secure", "app", "dev", "test", "staging", "admin",
    "portal", "cloud", "web", "files", "media", "assets", "data",
    "update", "download", "upload", "sync", "beta", "v2", "v1",
]
RANDOM_DOMAIN_WORDS = [
    "cloud", "data", "net", "host", "server", "tech", "soft", "web",
    "link", "core", "prime", "smart", "fast", "easy", "pro", "hub",
    "lab", "code", "byte", "bit", "geo", "cyber", "info", "media",
    "trend", "spot", "zone", "space", "site", "online",
]
RANDOM_TLDS = [
    "com", "ru", "net", "org", "io", "dev", "app", "info",
    "xyz", "top", "site", "online", "cc", "biz",
]
RANDOM_TLDS_SUSPICIOUS = [
    "xyz", "top", "club", "work", "click", "link", "gq", "cf",
    "tk", "ml", "ga", "buzz", "rest", "surf",
]

RANDOM_URL_PATHS = [
    "index.html", "login", "admin", "api/v1", "download", "upload",
    "files", "data", "user", "profile", "settings", "search", "page",
    "product", "item", "cart", "checkout", "auth", "signin", "register",
    "static/js/app.js", "static/css/style.css", "images/logo.png",
    "wp-admin", "wp-content", "phpmyadmin", "backup.zip", "config.php",
    "update.exe", "installer.msi", "payload.bin", "shell.php",
]
RANDOM_URL_PARAMS = [
    "id=1", "user=admin", "page=home", "q=test", "token=abc123",
    "session=xyz", "key=secret", "file=doc.pdf", "cmd=run", "exec=1",
    "redirect=http://evil.example", "url=javascript:alert(1)",
]

# ============================================================
# ПРЕСЕТЫ ПОЧТОВЫХ СЕРВИСОВ
# ============================================================
EMAIL_PRESETS = {
    "yandex":  {"name": "Яндекс",      "host": "smtp.yandex.ru",  "port": 465,
                "note": "Нужен пароль приложения (16 символов)"},
    "gmail":   {"name": "Gmail",       "host": "smtp.gmail.com",  "port": 587,
                "note": "Нужен пароль приложения (16 символов)"},
    "mailru":  {"name": "Mail.ru",     "host": "smtp.mail.ru",    "port": 465,
                "note": "Пароль приложения или обычный пароль"},
    "custom":  {"name": "Другой SMTP", "host": "",                "port": 587,
                "note": "Введите хост и порт вручную"},
}

DEFAULT_USER_CONFIG = {
    "vt_api_key": "",
    "vt_mode": "real",
    "email_enabled": True,
    "email_provider": "yandex",
    "email_smtp_host": "smtp.yandex.ru",
    "email_smtp_port": 465,
    "email_from": "",
    "email_to": "",
    "email_app_pass": "",
    "telegram_enabled": False,
    "telegram_bot_token": "",
    "telegram_chat_id": ""
}

# ============================================================
# АДМИН
# ============================================================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

if not is_admin():
    print("[*] Запрос прав администратора...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

def emergency_stop_suricata():
    global active_suricata_process
    if active_suricata_process is not None:
        try:
            active_suricata_process.kill()
        except Exception:
            pass
        active_suricata_process = None

atexit.register(emergency_stop_suricata)

def show_popup(title, message):
    try:
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x40 | 0x1000)
    except Exception:
        pass

# ============================================================
# РАБОТА С API-КЛЮЧОМ VIRUSTOTAL
# ============================================================
def get_vt_api_key():
    cfg = USER_CONFIG or load_user_config() or {}
    return str(cfg.get("vt_api_key", "")).strip()

def vt_headers():
    return {"x-apikey": get_vt_api_key()}

# ============================================================
# КОНФИГ
# ============================================================
def load_user_config():
    if not os.path.exists(USER_CONFIG_FILE):
        return None
    try:
        with open(USER_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = DEFAULT_USER_CONFIG.copy()
        merged.update(data)
        return merged
    except Exception as e:
        print(f"[!] Ошибка чтения config.json: {e}")
        return None


def save_user_config(cfg):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(USER_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4, ensure_ascii=False)
        print(f"[+] Настройки сохранены: {USER_CONFIG_FILE}")
    except Exception as e:
        print(f"[!] Ошибка сохранения config.json: {e}")


def choose_email_provider_interactive(cfg):
    print()
    print("   Выберите почтовый сервис:")
    print("     1. Яндекс (рекомендуется)")
    print("     2. Gmail")
    print("     3. Mail.ru")
    print("     4. Другой SMTP-сервер")
    p = input("   Ваш выбор (1-4) [1]: ").strip()

    if p == "2":   key = "gmail"
    elif p == "3": key = "mailru"
    elif p == "4": key = "custom"
    else:          key = "yandex"

    cfg["email_provider"] = key
    preset = EMAIL_PRESETS[key]
    cfg["email_smtp_host"] = preset["host"] or "smtp.example.com"
    cfg["email_smtp_port"] = preset["port"]

    print(f"   [{preset['name']}] {preset['note']}")

    if key == "custom":
        print("   SMTP-хост (например, smtp.example.com):")
        v = input("   > ").strip()
        if v: cfg["email_smtp_host"] = v
        print("   SMTP-порт (например, 587 или 465):")
        v = input("   > ").strip()
        if v.isdigit(): cfg["email_smtp_port"] = int(v)

    return cfg


def _try_send_test_email(host, port, email_from, email_to, app_pass):
    msg = MIMEMultipart()
    msg["From"]    = email_from
    msg["To"]      = email_to
    msg["Subject"] = "✅ Suricata Monitor: проверка пароля приложения"
    body = (
        "Это тестовое письмо от Suricata Monitor.\n\n"
        "Если вы его получили — пароль приложения указан корректно.\n\n"
        f"SMTP: {host}:{port}\n"
        f"От:   {email_from}\n"
        f"Кому: {email_to}\n"
        f"Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()
        server.login(email_from, app_pass)
        server.sendmail(email_from, email_to, msg.as_string())
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"   [!] Ошибка авторизации: {e}")
        print("       Проверьте пароль приложения (не обычный пароль!).")
        return False
    except Exception as e:
        print(f"   [!] Ошибка: {e}")
        return False


def input_app_password_with_check(cfg):
    host = cfg.get("email_smtp_host", "smtp.yandex.ru")
    port = int(cfg.get("email_smtp_port", 465))
    email_from = cfg.get("email_from", "")
    email_to   = cfg.get("email_to", "")

    if not email_from or not email_to:
        print("   [!] Сначала нужно указать email отправителя и получателя.")
        return None

    while True:
        print()
        print("   Введите ПАРОЛЬ ПРИЛОЖЕНИЯ (16 символов, без пробелов).")
        print("   Для выхода оставьте пустым и нажмите Enter.")
        pwd = input("   > ").strip().replace(" ", "")

        if not pwd:
            print("   [!] Пароль не введён.")
            return None

        print()
        print("   [*] Проверяю пароль: отправляю тестовое письмо...")
        ok = _try_send_test_email(host, port, email_from, email_to, pwd)

        if ok:
            print("   [✓] Пароль работает. Письмо успешно отправлено.")
            return pwd
        else:
            print()
            print("   [!] Не удалось отправить письмо с этим паролем.")
            retry = input("   Попробовать снова? (y/n) [y]: ").strip().lower()
            if retry in ("n", "no", "нет"):
                return None


def first_run_setup():
    print()
    print("=" * 70)
    print("   ПЕРВОНАЧАЛЬНАЯ НАСТРОЙКА")
    print("=" * 70)
    print()
    print("   Мастер запускается один раз при первом старте.")
    print("   Все введённые данные сохранятся в data/config.json.")
    print()
    print("=" * 70)

    cfg = DEFAULT_USER_CONFIG.copy()

    # --- Режим VirusTotal ---
    print()
    print("─── РЕЖИМ VIRUSTOTAL ────────────────────────────────────")
    print("   1. Реальный API (нужен интернет, лимит 4 запроса/мин)")
    print("   2. Имитация (без интернета, данные из data/ip_list.json)")
    mode_choice = input("   Ваш выбор (1-2) [1]: ").strip()
    cfg["vt_mode"] = "fake" if mode_choice == "2" else "real"
    print(f"   Режим: {'ИМИТАЦИЯ' if cfg['vt_mode'] == 'fake' else 'РЕАЛЬНЫЙ API'}")

    # --- Ключ VirusTotal ---
    if cfg["vt_mode"] == "real":
        print()
        print("─── API-КЛЮЧ VIRUSTOTAL ─────────────────────────────────")
        print("   Получить: https://www.virustotal.com/gui/my-apikey")
        print("   (Enter — оставить пустым, введёте позже в настройках)")
        v = input("   Введите API-ключ: ").strip()
        if v:
            cfg["vt_api_key"] = v

    # --- Email ---
    print()
    print("─── EMAIL-УВЕДОМЛЕНИЯ ───────────────────────────────────")
    enable_email = input("   Включить email-уведомления? (y/n) [y]: ").strip().lower()
    cfg["email_enabled"] = enable_email not in ("n", "no", "нет")

    if cfg["email_enabled"]:
        cfg = choose_email_provider_interactive(cfg)

        print()
        print("   Email-адрес, С КОТОРОГО отправлять (отправитель):")
        cfg["email_from"] = input("   > ").strip()

        print()
        print("   Email-адрес, НА КОТОРЫЙ присылать уведомления (получатель):")
        print("   (Enter — отправлять на тот же адрес, что и отправитель)")
        to_input = input("   > ").strip()
        cfg["email_to"] = to_input or cfg["email_from"]

        pwd = input_app_password_with_check(cfg)
        if pwd:
            cfg["email_app_pass"] = pwd
        else:
            print()
            print("   [!] Пароль не подтверждён. Email-уведомления отключены.")
            cfg["email_enabled"] = False

    # --- Telegram ---
    print()
    print("─── TELEGRAM-УВЕДОМЛЕНИЯ ────────────────────────────────")
    enable_tg = input("   Включить Telegram-уведомления? (y/n) [n]: ").strip().lower()
    cfg["telegram_enabled"] = enable_tg in ("y", "yes", "да")

    if cfg["telegram_enabled"]:
        print("   Токен бота от @BotFather:")
        cfg["telegram_bot_token"] = input("   > ").strip()
        print("   Ваш Chat ID от @userinfobot:")
        cfg["telegram_chat_id"] = input("   > ").strip()

    # --- Итог ---
    print()
    print("=" * 70)
    print("   ПРОВЕРЬТЕ ВВЕДЁННЫЕ ДАННЫЕ:")
    print("=" * 70)
    print(f"   Режим VirusTotal:  {'ИМИТАЦИЯ' if cfg['vt_mode'] == 'fake' else 'РЕАЛЬНЫЙ API'}")
    key = cfg.get("vt_api_key", "")
    print(f"   API-ключ VT:       {'задан' if key else '(не задан)'}")
    print(f"   Email включён:     {cfg['email_enabled']}")
    if cfg["email_enabled"]:
        pname = EMAIL_PRESETS.get(cfg.get("email_provider", ""), {}).get("name", "SMTP")
        print(f"   Сервис:            {pname}")
        print(f"   SMTP:              {cfg['email_smtp_host']}:{cfg['email_smtp_port']}")
        print(f"   От:                {cfg['email_from']}")
        print(f"   Кому:              {cfg['email_to']}")
        print(f"   Пароль приложения: {'*' * len(cfg['email_app_pass'])}")
    print(f"   Telegram включён:  {cfg['telegram_enabled']}")
    if cfg["telegram_enabled"]:
        print(f"   Bot Token:         {cfg['telegram_bot_token'][:10]}...")
        print(f"   Chat ID:           {cfg['telegram_chat_id']}")
    print("=" * 70)

    save = input("   Сохранить эти настройки? (y/n) [y]: ").strip().lower()
    if save in ("n", "no", "нет"):
        print("\n[!] Настройка отменена. Уведомления будут отключены.")
        cfg = DEFAULT_USER_CONFIG.copy()
        cfg["email_enabled"] = False
        cfg["telegram_enabled"] = False

    save_user_config(cfg)
    return cfg


def ensure_user_config():
    cfg = load_user_config()
    if cfg is None:
        cfg = first_run_setup()
    return cfg

# ============================================================
# EMAIL
# ============================================================
def send_email_alert(ip, risk_level, total_detections, source=""):
    cfg = USER_CONFIG or {}
    if not cfg.get("email_enabled", False):
        return
    email_from = cfg.get("email_from", "")
    email_to   = cfg.get("email_to", "")
    app_pass   = cfg.get("email_app_pass", "")
    host       = cfg.get("email_smtp_host", "smtp.yandex.ru")
    port       = int(cfg.get("email_smtp_port", 465))

    if not email_from or not app_pass or not email_to:
        print("  [!] Email не настроен. Зайдите в «Настройки уведомлений».")
        return

    subject = f"🚨 Suricata Monitor: обнаружена угроза {ip}"
    body = (
        f"ОБНАРУЖЕНА УГРОЗА\n"
        f"========================================\n\n"
        f"IP-адрес:            {ip}\n"
        f"Уровень риска:       {risk_level}\n"
        f"Обнаружений:         {total_detections}\n"
    )
    if source:
        body += f"Источник:            {source}\n"
    body += (
        f"\nВремя:               {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"\n--\nSuricata Monitor\n"
    )

    msg = MIMEMultipart()
    msg["From"]    = email_from
    msg["To"]      = email_to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()
        server.login(email_from, app_pass)
        server.sendmail(email_from, email_to, msg.as_string())
        server.quit()
        print(f"  [✓] Email отправлен на {email_to}")
    except smtplib.SMTPAuthenticationError:
        print("  [!] Ошибка авторизации email. Проверьте пароль приложения.")
    except Exception as e:
        print(f"  [!] Не удалось отправить email: {e}")

# ============================================================
# TELEGRAM
# ============================================================
def send_telegram_alert(ip, risk_level, total_detections, source=""):
    cfg = USER_CONFIG or {}
    if not cfg.get("telegram_enabled", False):
        return
    token   = cfg.get("telegram_bot_token", "")
    chat_id = cfg.get("telegram_chat_id", "")
    if not token or not chat_id:
        print("  [!] Telegram не настроен.")
        return

    text = (
        f"🚨 *ОБНАРУЖЕНА УГРОЗА*\n\n"
        f"🌐 IP: `{ip}`\n"
        f"⚠️ Уровень риска: *{risk_level}*\n"
        f"🔎 Обнаружений: `{total_detections}`\n"
    )
    if source:
        text += f"📡 Источник: {source}\n"
    text += f"\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id, "text": text, "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }
    try:
        r = requests.post(url, data=payload, timeout=10)
        if r.status_code == 200:
            print("  [✓] Уведомление отправлено в Telegram.")
        else:
            print(f"  [!] Ошибка Telegram: {r.status_code}")
    except Exception as e:
        print(f"  [!] Не удалось отправить в Telegram: {e}")


def notify_all(ip, risk_level, total_detections, source=""):
    send_email_alert(ip, risk_level, total_detections, source)
    send_telegram_alert(ip, risk_level, total_detections, source)

# ============================================================
# ФАЙЛ ip_list.json — создание образца
# ============================================================
def create_default_ip_list_file():
    sample = {
        "comment": (
            "Имитация DNS-событий Suricata и ответов VirusTotal. "
            "Используется только в режиме ИМИТАЦИИ."
        ),
        "dns_events": [
            {"src_ip": "172.20.10.8", "rrname": "google.com",       "count": 45},
            {"src_ip": "8.8.8.8",     "rrname": "dns.google",       "count": 30},
            {"src_ip": "77.88.8.8",   "rrname": "yandex.ru",        "count": 20},
            {"src_ip": "8.8.8.100",   "rrname": "malware.example",  "count": 5},
            {"src_ip": "1.1.1.50",    "rrname": "suspicious.example","count": 3},
            {"src_ip": "1.1.1.5",     "rrname": "low-risk.example", "count": 3},
            {"src_ip": "1.1.1.1",     "rrname": "cloudflare.com",   "count": 12}
        ],
        "vt_responses": {
            "8.8.8.100": {"malicious": True,  "risk_level": "КРИТИЧЕСКИЙ",
                          "malicious_count": 10, "suspicious_count": 2},
            "1.1.1.50":  {"malicious": True,  "risk_level": "ВЫСОКИЙ",
                          "malicious_count": 3,  "suspicious_count": 1},
            "1.1.1.5":   {"malicious": False, "risk_level": "НИЗКИЙ",
                          "malicious_count": 1,  "suspicious_count": 0},
            "1.1.1.1":   {"malicious": False, "risk_level": "ЧИСТЫЙ",
                          "malicious_count": 0,  "suspicious_count": 0},
            "8.8.8.8":   {"malicious": False, "risk_level": "ЧИСТЫЙ",
                          "malicious_count": 0,  "suspicious_count": 0},
            "77.88.8.8": {"malicious": False, "risk_level": "ЧИСТЫЙ",
                          "malicious_count": 0,  "suspicious_count": 0},
            "172.20.10.8":{"malicious": False,"risk_level": "ЧИСТЫЙ",
                          "malicious_count": 0,  "suspicious_count": 0}
        },
        "default_vt_response": {
            "malicious": False,
            "risk_level": "ЧИСТЫЙ",
            "malicious_count": 0,
            "suspicious_count": 0
        }
    }
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
            json.dump(sample, f, indent=4, ensure_ascii=False)
        print(f"  [+] Создан образец: {IP_LIST_FILE}")
    except Exception as e:
        print(f"  [!] Не удалось создать {IP_LIST_FILE}: {e}")

# ============================================================
# ГЕНЕРАТОР ПОЛНОСТЬЮ СЛУЧАЙНЫХ ДАННЫХ
# ============================================================
def _random_string(length=6, digits_only=False, letters_only=False):
    """Случайная строка из букв/цифр."""
    if digits_only:
        alphabet = string.digits
    elif letters_only:
        alphabet = string.ascii_lowercase
    else:
        alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _generate_random_domain(suspicious=False):
    """
    Генерирует СЛУЧАЙНЫЙ домен по буквам/цифрам.
    Примеры: 'a7k3f9.cloud-data.xyz', 'api2.fast-host.top'
    """
    sub = random.choice(RANDOM_SUBDOMAINS)
    word1 = random.choice(RANDOM_DOMAIN_WORDS)
    word2 = random.choice(RANDOM_DOMAIN_WORDS)
    digits = _random_string(random.randint(1, 4), digits_only=True)

    patterns = [
        f"{word1}{word2}",
        f"{word1}-{word2}",
        f"{word1}{digits}",
        f"{word1}-{digits}",
        f"{_random_string(random.randint(4, 8), letters_only=True)}",
        f"{word1}{_random_string(random.randint(2, 5))}",
    ]
    name = random.choice(patterns)

    tld_pool = RANDOM_TLDS_SUSPICIOUS if suspicious else RANDOM_TLDS
    tld = random.choice(tld_pool)

    if sub:
        return f"{sub}.{name}.{tld}"
    return f"{name}.{tld}"


def _generate_random_ip(suspicious=False):
    """Генерирует СЛУЧАЙНЫЙ IP-адрес."""
    if suspicious:
        first_octet = random.choice([5, 45, 91, 103, 141, 185, 193, 194])
    else:
        first_octet = random.choice([8, 77, 87, 93, 172, 192, 213])

    if first_octet == 172:
        second = random.randint(16, 31)
    elif first_octet == 192:
        second = 168
    else:
        second = random.randint(0, 255)

    third = random.randint(0, 255)
    fourth = random.randint(1, 254)

    return f"{first_octet}.{second}.{third}.{fourth}"


def _generate_random_url(suspicious=False):
    """
    Генерирует СЛУЧАЙНЫЙ URL.
    Пример: 'http://xk42j.cloud-data.xyz/login?id=1'
    """
    domain = _generate_random_domain(suspicious=suspicious)
    scheme = "http" if suspicious else random.choice(["https", "https", "https", "http"])
    path = random.choice(RANDOM_URL_PATHS)

    # В 30% случаев добавляем параметры
    if random.random() < 0.3:
        param = random.choice(RANDOM_URL_PARAMS)
        return f"{scheme}://{domain}/{path}?{param}"
    return f"{scheme}://{domain}/{path}"


def generate_random_fake_data(
    num_ips=8,
    num_domains=10,
    num_urls=8,
    bad_ratio=0.3,
):
    """
    Генерирует ПОЛНОСТЬЮ СЛУЧАЙНЫЕ данные для имитации:
    - IP-адреса: из букв/цифр — рандомно
    - домены: из букв/цифр — рандомно
    - URL: из букв/цифр — рандомно
    - вердикты VT: рандомно
    - количество DNS: рандомно
    """
    dns_events = []
    url_events = []
    vt_responses = {}

    # --- Считаем, сколько опасных ---
    safe_ips_count = int(num_ips * (1 - bad_ratio))
    bad_ips_count = num_ips - safe_ips_count

    safe_dom_count = int(num_domains * (1 - bad_ratio))
    bad_dom_count = num_domains - safe_dom_count

    safe_url_count = int(num_urls * (1 - bad_ratio))
    bad_url_count = num_urls - safe_url_count

    # --- Генерируем IP ---
    generated_ips = set()
    all_ips = []

    while len([x for x in all_ips if not x[1]]) < safe_ips_count:
        ip = _generate_random_ip(suspicious=False)
        if ip in generated_ips:
            continue
        generated_ips.add(ip)
        all_ips.append((ip, False))

    while len([x for x in all_ips if x[1]]) < bad_ips_count:
        ip = _generate_random_ip(suspicious=True)
        if ip in generated_ips:
            continue
        generated_ips.add(ip)
        all_ips.append((ip, True))

    random.shuffle(all_ips)

    # --- Генерируем домены ---
    generated_domains = set()
    all_domains = []

    while len([x for x in all_domains if not x[1]]) < safe_dom_count:
        d = _generate_random_domain(suspicious=False)
        if d in generated_domains:
            continue
        generated_domains.add(d)
        all_domains.append((d, False))

    while len([x for x in all_domains if x[1]]) < bad_dom_count:
        d = _generate_random_domain(suspicious=True)
        if d in generated_domains:
            continue
        generated_domains.add(d)
        all_domains.append((d, True))

    random.shuffle(all_domains)

    # --- Генерируем URL ---
    generated_urls = set()
    all_urls = []

    while len([x for x in all_urls if not x[1]]) < safe_url_count:
        u = _generate_random_url(suspicious=False)
        if u in generated_urls:
            continue
        generated_urls.add(u)
        all_urls.append((u, False))

    while len([x for x in all_urls if x[1]]) < bad_url_count:
        u = _generate_random_url(suspicious=True)
        if u in generated_urls:
            continue
        generated_urls.add(u)
        all_urls.append((u, True))

    random.shuffle(all_urls)

    # --- Формируем dns_events ---
    # count от 3 до 100, чтобы все IP прошли DNS_THRESHOLD = 2
    for ip, _ in all_ips:
        n_domains = random.randint(1, 3)
        for _ in range(n_domains):
            domain, _ = random.choice(all_domains)
            count = random.randint(3, 100)
            dns_events.append({
                "src_ip": ip,
                "rrname": domain,
                "count": count,
            })

    # --- Формируем url_events ---
    for ip, _ in all_ips:
        if random.random() < 0.6:
            n_urls = random.randint(1, 2)
            for _ in range(n_urls):
                url, _ = random.choice(all_urls)
                count = random.randint(1, 20)
                url_events.append({
                    "src_ip": ip,
                    "url": url,
                    "count": count,
                })

    # --- Формируем vt_responses для IP ---
    for ip, is_bad in all_ips:
        if is_bad:
            malicious = random.randint(2, 20)
            suspicious = random.randint(0, 5)
            total = malicious + suspicious
            if total >= 10: risk = "КРИТИЧЕСКИЙ"
            elif total >= 5: risk = "ВЫСОКИЙ"
            elif total >= 2: risk = "НИЗКИЙ"
            else: risk = "ЧИСТЫЙ"
            vt_responses[ip] = {
                "malicious": True, "risk_level": risk,
                "malicious_count": malicious, "suspicious_count": suspicious,
            }
        else:
            vt_responses[ip] = {
                "malicious": False, "risk_level": "ЧИСТЫЙ",
                "malicious_count": 0, "suspicious_count": 0,
            }

    # --- Формируем vt_responses для доменов ---
    for domain, is_bad in all_domains:
        if is_bad:
            malicious = random.randint(1, 12)
            suspicious = random.randint(0, 3)
            total = malicious + suspicious
            if total >= 10: risk = "КРИТИЧЕСКИЙ"
            elif total >= 5: risk = "ВЫСОКИЙ"
            elif total >= 1: risk = "НИЗКИЙ"
            else: risk = "ЧИСТЫЙ"
            vt_responses[domain] = {
                "malicious": True, "risk_level": risk,
                "malicious_count": malicious, "suspicious_count": suspicious,
            }
        else:
            vt_responses[domain] = {
                "malicious": False, "risk_level": "ЧИСТЫЙ",
                "malicious_count": 0, "suspicious_count": 0,
            }

    # --- Формируем vt_responses для URL ---
    for url, is_bad in all_urls:
        if is_bad:
            malicious = random.randint(1, 10)
            suspicious = random.randint(0, 3)
            total = malicious + suspicious
            if total >= 8: risk = "КРИТИЧЕСКИЙ"
            elif total >= 4: risk = "ВЫСОКИЙ"
            elif total >= 1: risk = "НИЗКИЙ"
            else: risk = "ЧИСТЫЙ"
            vt_responses[url] = {
                "malicious": True, "risk_level": risk,
                "malicious_count": malicious, "suspicious_count": suspicious,
            }
        else:
            vt_responses[url] = {
                "malicious": False, "risk_level": "ЧИСТЫЙ",
                "malicious_count": 0, "suspicious_count": 0,
            }

    data = {
        "comment": (
            "АВТОСГЕНЕРИРОВАННЫЕ (ПОЛНОСТЬЮ СЛУЧАЙНЫЕ) данные для имитации. "
            f"Создано: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ),
        "dns_events": dns_events,
        "url_events": url_events,
        "vt_responses": vt_responses,
        "default_vt_response": {
            "malicious": False, "risk_level": "ЧИСТЫЙ",
            "malicious_count": 0, "suspicious_count": 0,
        },
    }
    return data


def regenerate_fake_data_file(
    num_ips=8, num_domains=10, num_urls=8, bad_ratio=0.3,
):
    """Генерирует и сохраняет файл data/ip_list_generated.json."""
    data = generate_random_fake_data(num_ips, num_domains, num_urls, bad_ratio)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(FAKE_GENERATED_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"  [+] Сгенерированы случайные данные: {FAKE_GENERATED_FILE}")
        print(f"      DNS-событий: {len(data['dns_events'])}, "
              f"URL-событий: {len(data.get('url_events', []))}, "
              f"записей VT: {len(data['vt_responses'])}")
    except Exception as e:
        print(f"  [!] Ошибка сохранения: {e}")
    return data

# ============================================================
# ИМИТАЦИЯ — анализ DNS-событий (с приоритетом generated)
# ============================================================
def analyze_eve_fake():
    global LAST_DOMAINS, LAST_URLS

    src_file = FAKE_GENERATED_FILE if os.path.exists(FAKE_GENERATED_FILE) else IP_LIST_FILE
    print(f"  [FAKE] Читаю DNS-события из {src_file}...")

    if not os.path.exists(src_file):
        print(f"  [!] Файл {src_file} не найден — создаю образец.")
        create_default_ip_list_file()
        src_file = IP_LIST_FILE

    try:
        with open(src_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"  [!] Ошибка чтения: {e}")
        return pd.DataFrame()

    dns_events = data.get("dns_events", [])
    if not dns_events:
        print("  [!] В файле нет DNS-событий (раздел dns_events).")
        return pd.DataFrame()

    # --- Собираем IP ---
    dns_count = {}
    # --- Собираем домены ---
    domains_set = set()

    for ev in dns_events:
        ip = str(ev.get("src_ip", "")).strip()
        cnt = int(ev.get("count", 1))
        if ip:
            dns_count[ip] = dns_count.get(ip, 0) + cnt

        # собираем домены из rrname
        rrname = str(ev.get("rrname", "")).strip().rstrip(".").lower()
        if rrname:
            domains_set.add(rrname)

    # URL из url_events
    urls_set = set()
    url_events = data.get("url_events", [])
    for ev in url_events:
        u = str(ev.get("url", "")).strip()
        if u:
            urls_set.add(u)

    # если url_events нет — попробуем собрать URL из vt_responses
    if not urls_set:
        vt_resp = data.get("vt_responses", {})
        for key in vt_resp.keys():
            if key.startswith("http://") or key.startswith("https://"):
                urls_set.add(key)

    # если domains нет — попробуем собрать домены из vt_responses
    if not domains_set:
        vt_resp = data.get("vt_responses", {})
        for key in vt_resp.keys():
            if key.startswith("http://") or key.startswith("https://"):
                continue
            parts = key.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                continue
            if "." in key:
                domains_set.add(key)

    LAST_DOMAINS = list(domains_set)[:5]
    LAST_URLS = list(urls_set)[:8]

    print(f"  [+] Имитация: событий {len(dns_events)}, "
          f"уникальных IP {len(dns_count)}, "
          f"доменов {len(LAST_DOMAINS)}, URL {len(LAST_URLS)}.")

    return pd.DataFrame(list(dns_count.items()), columns=["ip", "dns_requests"])

# ============================================================
# ИМИТАЦИЯ VIRUSTOTAL — IP (с приоритетом generated)
# ============================================================
def check_ip_virustotal_fake(ip_address):
    print(f"  [FAKE] Имитация VT для {ip_address}...")

    default = {"malicious": False, "risk_level": "ЧИСТЫЙ",
               "malicious_count": 0, "suspicious_count": 0}
    data = None
    src_file = FAKE_GENERATED_FILE if os.path.exists(FAKE_GENERATED_FILE) else IP_LIST_FILE

    if os.path.exists(src_file):
        try:
            with open(src_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"  [!] Ошибка чтения {src_file}: {e}")
    else:
        create_default_ip_list_file()
        try:
            with open(IP_LIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass

    if data:
        if isinstance(data.get("default_vt_response"), dict):
            default.update(data["default_vt_response"])
        vt_resp = data.get("vt_responses", {})
        if ip_address in vt_resp and isinstance(vt_resp[ip_address], dict):
            entry = vt_resp[ip_address]
            result = {
                "malicious": bool(entry.get("malicious", default["malicious"])),
                "risk_level": str(entry.get("risk_level", default["risk_level"])),
                "malicious_count": int(entry.get("malicious_count", 0)),
                "suspicious_count": int(entry.get("suspicious_count", 0)),
            }
            source_note = "vt_responses"
        else:
            result = dict(default)
            source_note = "default_vt_response"
    else:
        result = default
        source_note = "fallback"

    total = result["malicious_count"] + result["suspicious_count"]
    time.sleep(0.05)

    return {
        "ip": ip_address, "malicious": result["malicious"],
        "malicious_count": result["malicious_count"],
        "suspicious_count": result["suspicious_count"],
        "harmless_count": 0, "undetected_count": 0,
        "total_detections": total, "risk_level": result["risk_level"],
        "source": f"VirusTotal (IMITATION: {source_note})"
    }

# ============================================================
# РЕАЛЬНЫЙ VIRUSTOTAL — IP
# ============================================================
def check_ip_virustotal(ip_address):
    if VT_MODE == "fake":
        return check_ip_virustotal_fake(ip_address)

    api_key = get_vt_api_key()
    if not api_key:
        print("  [!] API-ключ VirusTotal не задан.")
        return {"ip": ip_address, "malicious": False,
                "total_detections": 0, "risk_level": "НЕ НАСТРОЕН",
                "source": "No API key"}

    print(f"  [API] Проверка IP {ip_address} через VirusTotal...")
    try:
        response = requests.get(VT_URL.format(ip_address),
                                headers=vt_headers(), timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total_detections = malicious + suspicious
            is_bad = total_detections >= MALICIOUS_THRESHOLD

            if total_detections >= 5:   risk_level = "КРИТИЧЕСКИЙ"
            elif total_detections >= 2: risk_level = "ВЫСОКИЙ"
            elif total_detections == 1: risk_level = "НИЗКИЙ"
            else:                       risk_level = "ЧИСТЫЙ"

            return {"ip": ip_address, "malicious": is_bad,
                    "malicious_count": malicious, "suspicious_count": suspicious,
                    "harmless_count": harmless, "undetected_count": undetected,
                    "total_detections": total_detections, "risk_level": risk_level,
                    "source": "VirusTotal (Real API)"}
        elif response.status_code == 401:
            print("  [!] Ошибка авторизации VirusTotal (401).")
            return {"ip": ip_address, "malicious": False, "total_detections": 0,
                    "risk_level": "НЕ АВТОРИЗОВАН", "source": "HTTP 401"}
        elif response.status_code == 429:
            print("  [!] Превышен лимит запросов к VirusTotal (429).")
            return {"ip": ip_address, "malicious": False, "total_detections": 0,
                    "risk_level": "НЕИЗВЕСТНО", "source": "Rate limit"}
        elif response.status_code == 404:
            print(f"  [?] IP {ip_address} не найден в базе VirusTotal.")
            return {"ip": ip_address, "malicious": False, "total_detections": 0,
                    "risk_level": "НЕТ ДАННЫХ", "source": "Not found in VT"}
        else:
            print(f"  [!] Ошибка API: {response.status_code}")
            return {"ip": ip_address, "malicious": False, "total_detections": 0,
                    "risk_level": "ОШИБКА", "source": f"HTTP {response.status_code}"}
    except requests.exceptions.Timeout:
        print("  [!] Таймаут при запросе к VirusTotal.")
        return {"ip": ip_address, "malicious": False, "total_detections": 0,
                "risk_level": "ТАЙМАУТ", "source": "Timeout"}
    except Exception as e:
        print(f"  [!] Ошибка запроса: {e}")
        return {"ip": ip_address, "malicious": False, "total_detections": 0,
                "risk_level": "ОШИБКА", "source": f"Error: {e}"}

# ============================================================
# РЕАЛЬНЫЙ VIRUSTOTAL — ДОМЕН (с кэшем и с fake-веткой)
# ============================================================
def check_domain_virustotal(domain):
    """Проверяет домен через VirusTotal API (с кэшем)."""
    if domain in DOMAIN_CACHE:
        print(f"  [CACHE] Домен {domain} — уже проверялся ранее.")
        return DOMAIN_CACHE[domain]

    if VT_MODE == "fake":
        data = None
        src_file = FAKE_GENERATED_FILE if os.path.exists(FAKE_GENERATED_FILE) else IP_LIST_FILE
        if os.path.exists(src_file):
            try:
                with open(src_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                pass

        if data and domain in data.get("vt_responses", {}):
            entry = data["vt_responses"][domain]
            malicious = bool(entry.get("malicious", False))
            mc = int(entry.get("malicious_count", 0))
            sc = int(entry.get("suspicious_count", 0))
            total = mc + sc
            risk = str(entry.get("risk_level", "ЧИСТЫЙ"))
            result = {"domain": domain, "malicious": malicious,
                      "total_detections": total, "risk_level": risk,
                      "source": "VirusTotal (IMITATION: generated)"}
        else:
            result = {"domain": domain, "malicious": False,
                      "total_detections": 0, "risk_level": "ЧИСТЫЙ",
                      "source": "VirusTotal (IMITATION: default)"}
        DOMAIN_CACHE[domain] = result
        return result

    api_key = get_vt_api_key()
    if not api_key:
        return {"domain": domain, "malicious": False,
                "total_detections": 0, "risk_level": "НЕ НАСТРОЕН",
                "source": "No API key"}

    print(f"  [API] Проверка домена {domain} через VirusTotal...")
    try:
        r = requests.get(VT_URL_DOMAIN.format(domain),
                         headers=vt_headers(), timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = malicious + suspicious
            is_bad = total >= 1

            if total >= 5:   risk = "КРИТИЧЕСКИЙ"
            elif total >= 2: risk = "ВЫСОКИЙ"
            elif total == 1: risk = "НИЗКИЙ"
            else:            risk = "ЧИСТЫЙ"

            result = {"domain": domain, "malicious": is_bad,
                      "total_detections": total, "risk_level": risk,
                      "source": "VirusTotal (Real API)"}
            DOMAIN_CACHE[domain] = result
            return result
        elif r.status_code == 404:
            print(f"  [?] Домен {domain} не найден в базе VirusTotal.")
            result = {"domain": domain, "malicious": False,
                      "total_detections": 0, "risk_level": "НЕТ ДАННЫХ",
                      "source": "Not found in VT"}
            DOMAIN_CACHE[domain] = result
            return result
        elif r.status_code == 429:
            print("  [!] Превышен лимит запросов к VirusTotal (429).")
            return {"domain": domain, "malicious": False,
                    "total_detections": 0, "risk_level": "НЕИЗВЕСТНО",
                    "source": "Rate limit"}
        else:
            print(f"  [!] Ошибка API: {r.status_code}")
            return {"domain": domain, "malicious": False,
                    "total_detections": 0, "risk_level": "ОШИБКА",
                    "source": f"HTTP {r.status_code}"}
    except Exception as e:
        print(f"  [!] Ошибка запроса: {e}")
        return {"domain": domain, "malicious": False,
                "total_detections": 0, "risk_level": "ОШИБКА",
                "source": f"Error: {e}"}

# ============================================================
# РЕАЛЬНЫЙ VIRUSTOTAL — URL (POST → GET /analyses)
# ============================================================
def check_url_virustotal(url):
    """Проверяет URL через VirusTotal API v3 (POST → GET analyses)."""
    if url in URL_CACHE:
        print(f"  [CACHE] URL {url} — уже проверялся ранее.")
        return URL_CACHE[url]

    # --- ИМИТАЦИЯ ---
    if VT_MODE == "fake":
        data = None
        src_file = FAKE_GENERATED_FILE if os.path.exists(FAKE_GENERATED_FILE) else IP_LIST_FILE
        if os.path.exists(src_file):
            try:
                with open(src_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                pass

        if data and url in data.get("vt_responses", {}):
            entry = data["vt_responses"][url]
            malicious = bool(entry.get("malicious", False))
            mc = int(entry.get("malicious_count", 0))
            sc = int(entry.get("suspicious_count", 0))
            total = mc + sc
            risk = str(entry.get("risk_level", "ЧИСТЫЙ"))
            result = {"url": url, "malicious": malicious,
                      "total_detections": total, "risk_level": risk,
                      "source": "VirusTotal (IMITATION: generated)"}
        else:
            result = {"url": url, "malicious": False,
                      "total_detections": 0, "risk_level": "ЧИСТЫЙ",
                      "source": "VirusTotal (IMITATION: default)"}
        URL_CACHE[url] = result
        return result

    # --- РЕАЛЬНЫЙ РЕЖИМ ---
    api_key = get_vt_api_key()
    if not api_key:
        return {"url": url, "malicious": False,
                "total_detections": 0, "risk_level": "НЕ НАСТРОЕН",
                "source": "No API key"}

    print(f"  [API] Проверка URL {url} через VirusTotal...")

    try:
        # Шаг 1: отправляем URL на анализ (POST /urls)
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=vt_headers(),
            data={"url": url},
            timeout=15,
        )

        if r.status_code == 401:
            print("  [!] Ошибка авторизации VirusTotal (401).")
            return {"url": url, "malicious": False, "total_detections": 0,
                    "risk_level": "НЕ АВТОРИЗОВАН", "source": "HTTP 401"}

        if r.status_code == 429:
            print("  [!] Превышен лимит запросов к VirusTotal (429).")
            return {"url": url, "malicious": False, "total_detections": 0,
                    "risk_level": "НЕИЗВЕСТНО", "source": "Rate limit"}

        if r.status_code not in (200, 201):
            print(f"  [!] Ошибка API (POST): {r.status_code}")
            return {"url": url, "malicious": False, "total_detections": 0,
                    "risk_level": "ОШИБКА", "source": f"POST HTTP {r.status_code}"}

        # Шаг 2: получаем ID анализа
        try:
            info = r.json()
        except Exception as e:
            print(f"  [!] Ошибка разбора ответа: {e}")
            return {"url": url, "malicious": False, "total_detections": 0,
                    "risk_level": "ОШИБКА", "source": "JSON parse error"}

        analysis_id = info.get("data", {}).get("id")
        if not analysis_id:
            print("  [!] VirusTotal не вернул ID анализа.")
            return {"url": url, "malicious": False, "total_detections": 0,
                    "risk_level": "НЕТ ДАННЫХ", "source": "No analysis ID"}

        print(f"  [*] Analysis ID получен. Жду анализ (5 сек)...")

        # Шаг 3: ждём, пока VT проанализирует (5 сек)
        time.sleep(5)

        # Шаг 4: получаем результат анализа (GET /analyses/{id})
        r2 = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=vt_headers(),
            timeout=15,
        )

        if r2.status_code == 200:
            data = r2.json()
            attrs = data.get("data", {}).get("attributes", {})
            status = attrs.get("status", "")

            # Если анализ ещё идёт — возвращаем "В ОЧЕРЕДИ"
            if status != "completed":
                print(f"  [*] Анализ ещё идёт (status: {status}).")
                result = {"url": url, "malicious": False,
                          "total_detections": 0,
                          "risk_level": "В ОЧЕРЕДИ (VT анализирует)",
                          "source": f"VirusTotal (status: {status})"}
                URL_CACHE[url] = result
                return result

            stats = attrs.get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = malicious + suspicious
            is_bad = total >= 1

            if total >= 5:   risk = "КРИТИЧЕСКИЙ"
            elif total >= 2: risk = "ВЫСОКИЙ"
            elif total == 1: risk = "НИЗКИЙ"
            else:            risk = "ЧИСТЫЙ"

            result = {"url": url, "malicious": is_bad,
                      "total_detections": total, "risk_level": risk,
                      "source": "VirusTotal (Real API)"}
            URL_CACHE[url] = result
            return result

        elif r2.status_code == 404:
            print(f"  [?] Анализ {analysis_id} не найден.")
            result = {"url": url, "malicious": False,
                      "total_detections": 0, "risk_level": "НЕТ ДАННЫХ",
                      "source": "Analysis not found"}
            URL_CACHE[url] = result
            return result

        elif r2.status_code == 401:
            print("  [!] Ошибка авторизации VirusTotal (401).")
            return {"url": url, "malicious": False, "total_detections": 0,
                    "risk_level": "НЕ АВТОРИЗОВАН", "source": "HTTP 401"}

        elif r2.status_code == 429:
            print("  [!] Превышен лимит запросов к VirusTotal (429).")
            return {"url": url, "malicious": False, "total_detections": 0,
                    "risk_level": "НЕИЗВЕСТНО", "source": "Rate limit"}

        else:
            print(f"  [!] Ошибка API (GET analyses): {r2.status_code}")
            return {"url": url, "malicious": False, "total_detections": 0,
                    "risk_level": "ОШИБКА", "source": f"GET HTTP {r2.status_code}"}

    except requests.exceptions.Timeout:
        print("  [!] Таймаут при запросе к VirusTotal.")
        return {"url": url, "malicious": False, "total_detections": 0,
                "risk_level": "ТАЙМАУТ", "source": "Timeout"}

    except Exception as e:
        print(f"  [!] Ошибка запроса: {e}")
        return {"url": url, "malicious": False, "total_detections": 0,
                "risk_level": "ОШИБКА", "source": f"Error: {e}"}

# ============================================================
# SURICATA
# ============================================================
def start_suricata():
    global active_suricata_process
    print("[*] Запуск Suricata...")
    if not os.path.exists(SURICATA_EXE):
        print(f"[!] Не найден файл: {SURICATA_EXE}")
        return None
    os.makedirs(SURICATA_LOG_DIR, exist_ok=True)
    cmd = [SURICATA_EXE, "-c", SURICATA_CONFIG, "-l", SURICATA_LOG_DIR,
           "-S", SURICATA_RULES, "-i", INTERFACE]
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        print(f"[+] Suricata запущена. PID: {process.pid}")
        active_suricata_process = process
        return process
    except Exception as e:
        print(f"[!] Ошибка запуска Suricata: {e}")
        return None


def stop_suricata(process):
    global active_suricata_process
    if process is None:
        return
    print("[*] Остановка Suricata...")
    try:
        process.send_signal(signal.CTRL_BREAK_EVENT)
        process.wait(timeout=10)
        print("[+] Suricata остановлена.")
    except Exception:
        try: process.kill()
        except Exception: pass
    active_suricata_process = None

# ============================================================
# АНАЛИЗ eve.json — сбор IP, доменов и URL
# ============================================================
def analyze_eve(filepath):
    global LAST_DOMAINS, LAST_URLS

    if VT_MODE == "fake":
        return analyze_eve_fake()

    if not os.path.exists(filepath):
        print(f"[!] Файл {filepath} не найден.")
        return pd.DataFrame()

    dns_count = {}
    domains = set()
    urls = set()
    total_events = 0

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    total_events += 1
                    if event.get("event_type") == "dns":
                        src_ip = event.get("src_ip")
                        if src_ip:
                            dns_count[src_ip] = dns_count.get(src_ip, 0) + 1

                        dns_info = event.get("dns", {}) or {}
                        queries = dns_info.get("queries", [])
                        if isinstance(queries, list):
                            for q in queries:
                                if isinstance(q, dict):
                                    rrname = q.get("rrname")
                                    if rrname:
                                        rrname = str(rrname).strip().rstrip(".").lower()
                                        if rrname:
                                            domains.add(rrname)
                        rrname_top = dns_info.get("rrname")
                        if rrname_top:
                            rrname_top = str(rrname_top).strip().rstrip(".").lower()
                            if rrname_top:
                                domains.add(rrname_top)

                    # URL из HTTP-событий
                    elif event.get("event_type") == "http":
                        http_info = event.get("http", {}) or {}
                        hostname = http_info.get("hostname", "")
                        url_path = http_info.get("url", "")
                        if hostname and url_path:
                            full_url = f"http://{hostname}{url_path}"
                            urls.add(full_url)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[!] Ошибка чтения eve.json: {e}")
        return pd.DataFrame()

    print(f"[+] Всего событий: {total_events}")
    print(f"[+] Уникальных IP: {len(dns_count)}")
    print(f"[+] Уникальных доменов: {len(domains)}")
    print(f"[+] Уникальных URL: {len(urls)}")

    LAST_DOMAINS = list(domains)[:5]
    LAST_URLS = list(urls)[:8]

    return pd.DataFrame(list(dns_count.items()), columns=["ip", "dns_requests"])

# ============================================================
# БАЗА ДАННЫХ
# ============================================================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            total_suspicious INTEGER,
            total_blocked INTEGER,
            capture_time INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS found_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            dns_requests INTEGER,
            api_malicious BOOLEAN,
            blocked BOOLEAN,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS found_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            domain TEXT,
            risk_level TEXT,
            total_detections INTEGER,
            malicious BOOLEAN,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS found_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            url TEXT,
            risk_level TEXT,
            total_detections INTEGER,
            malicious BOOLEAN,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    """)
    conn.commit()
    conn.close()


def save_scan_to_db(report_data, blocked_ips, capture_time):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO scans (timestamp, total_suspicious, total_blocked, capture_time)
            VALUES (?, ?, ?, ?)
        """, (timestamp, len(report_data), len(blocked_ips), capture_time))
        scan_id = cursor.lastrowid
        for item in report_data:
            cursor.execute("""
                INSERT INTO found_ips (scan_id, ip, dns_requests, api_malicious, blocked)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, item["ip"], item["dns_requests"],
                  item["api_malicious"], item["ip"] in blocked_ips))
        conn.commit()
        conn.close()
        print(f"[+] Результаты сохранены в БД (scan_id={scan_id})")
    except Exception as e:
        print(f"[!] Ошибка сохранения в БД: {e}")


def save_domains_to_db(domains, cache):
    if not domains:
        return
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            conn.close()
            return
        scan_id = row[0]
        for domain in domains:
            info = cache.get(domain, {})
            cursor.execute("""
                INSERT INTO found_domains
                    (scan_id, domain, risk_level, total_detections, malicious)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, domain,
                  info.get("risk_level", "НЕИЗВЕСТНО"),
                  info.get("total_detections", 0),
                  bool(info.get("malicious", False))))
        conn.commit()
        conn.close()
        print(f"[+] Домены сохранены в БД (scan_id={scan_id}, {len(domains)} шт.)")
    except Exception as e:
        print(f"[!] Ошибка сохранения доменов в БД: {e}")


def save_urls_to_db(urls, cache):
    if not urls:
        return
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            conn.close()
            return
        scan_id = row[0]
        for url in urls:
            info = cache.get(url, {})
            cursor.execute("""
                INSERT INTO found_urls
                    (scan_id, url, risk_level, total_detections, malicious)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, url,
                  info.get("risk_level", "НЕИЗВЕСТНО"),
                  info.get("total_detections", 0),
                  bool(info.get("malicious", False))))
        conn.commit()
        conn.close()
        print(f"[+] URL сохранены в БД (scan_id={scan_id}, {len(urls)} шт.)")
    except Exception as e:
        print(f"[!] Ошибка сохранения URL в БД: {e}")

# ============================================================
# ГРАФИКИ ПО РЕЗУЛЬТАТАМ
# ============================================================
def build_domain_charts(domains, cache):
    if not domains:
        print("[i] Нет доменов для построения графиков.")
        return
    try:
        rows = []
        for domain in domains:
            info = cache.get(domain, {})
            rows.append({"domain": domain,
                         "detections": info.get("total_detections", 0),
                         "risk": info.get("risk_level", "НЕИЗВЕСТНО"),
                         "malicious": bool(info.get("malicious", False))})
        rows.sort(key=lambda x: x["detections"], reverse=True)
        top = rows[:10]

        if top:
            dom_names = [r["domain"] for r in top]
            det_counts = [r["detections"] for r in top]
            colors = ['red' if r["malicious"] else 'steelblue' for r in top]
            plt.figure(figsize=(12, 6))
            bars = plt.bar(dom_names, det_counts, color=colors)
            plt.title("Топ-10 доменов по обнаружениям VirusTotal")
            plt.xlabel("Домен"); plt.ylabel("Обнаружений")
            plt.xticks(rotation=45, ha="right")
            for bar in bars:
                h = bar.get_height()
                if h > 0:
                    plt.text(bar.get_x() + bar.get_width() / 2., h,
                             f'{int(h)}', ha='center', va='bottom', fontsize=9)
            plt.tight_layout()
            chart_dom_file = os.path.join(DATA_DIR, "suricata_domains_chart.png")
            plt.savefig(chart_dom_file, dpi=150); plt.close()
            print(f"[+] График доменов: {chart_dom_file}")

        risk_order = ["КРИТИЧЕСКИЙ", "ВЫСОКИЙ", "НИЗКИЙ", "ЧИСТЫЙ", "НЕИЗВЕСТНО"]
        counts = {level: 0 for level in risk_order}
        for r in rows:
            level = r["risk"]
            matched = False
            for key in risk_order:
                if key in level:
                    counts[key] += 1; matched = True; break
            if not matched: counts["НЕИЗВЕСТНО"] += 1

        labels = risk_order; sizes = [counts[l] for l in labels]
        colors_map = {"КРИТИЧЕСКИЙ": "#d32f2f", "ВЫСОКИЙ": "#f57c00",
                      "НИЗКИЙ": "#fbc02d", "ЧИСТЫЙ": "#388e3c",
                      "НЕИЗВЕСТНО": "#9e9e9e"}
        bar_colors = [colors_map[l] for l in labels]

        if sum(sizes) > 0:
            plt.figure(figsize=(8, 6))
            bars = plt.bar(labels, sizes, color=bar_colors)
            plt.title("Распределение доменов по уровням риска")
            plt.xlabel("Уровень риска"); plt.ylabel("Количество доменов")
            for bar in bars:
                h = bar.get_height()
                if h > 0:
                    plt.text(bar.get_x() + bar.get_width() / 2., h,
                             f'{int(h)}', ha='center', va='bottom', fontsize=10)
            plt.tight_layout()
            chart_risk_file = os.path.join(DATA_DIR, "suricata_domains_risk_chart.png")
            plt.savefig(chart_risk_file, dpi=150); plt.close()
            print(f"[+] График рисков доменов: {chart_risk_file}")
    except Exception as e:
        print(f"[!] Ошибка графиков доменов: {e}")


def build_url_charts(urls, cache):
    if not urls:
        print("[i] Нет URL для построения графиков.")
        return
    try:
        rows = []
        for url in urls:
            info = cache.get(url, {})
            rows.append({"url": url,
                         "detections": info.get("total_detections", 0),
                         "risk": info.get("risk_level", "НЕИЗВЕСТНО"),
                         "malicious": bool(info.get("malicious", False))})
        rows.sort(key=lambda x: x["detections"], reverse=True)
        top = rows[:10]

        if top:
            url_names = []
            for r in top:
                u = r["url"]
                url_names.append(u[:40] + ".." if len(u) > 42 else u)
            det_counts = [r["detections"] for r in top]
            colors = ['red' if r["malicious"] else 'steelblue' for r in top]

            plt.figure(figsize=(12, 7))
            bars = plt.barh(url_names, det_counts, color=colors)
            plt.title("Топ-10 URL по обнаружениям VirusTotal")
            plt.xlabel("Обнаружений"); plt.ylabel("URL")
            for bar in bars:
                h = bar.get_width()
                if h > 0:
                    plt.text(h, bar.get_y() + bar.get_height() / 2.,
                             f'{int(h)}', ha='left', va='center', fontsize=9)
            plt.tight_layout()
            chart_url_file = os.path.join(DATA_DIR, "suricata_urls_chart.png")
            plt.savefig(chart_url_file, dpi=150); plt.close()
            print(f"[+] График URL: {chart_url_file}")

        risk_order = ["КРИТИЧЕСКИЙ", "ВЫСОКИЙ", "НИЗКИЙ", "ЧИСТЫЙ", "НЕИЗВЕСТНО"]
        counts = {level: 0 for level in risk_order}
        for r in rows:
            level = r["risk"]
            matched = False
            for key in risk_order:
                if key in level:
                    counts[key] += 1; matched = True; break
            if not matched: counts["НЕИЗВЕСТНО"] += 1

        labels = risk_order; sizes = [counts[l] for l in labels]
        colors_map = {"КРИТИЧЕСКИЙ": "#d32f2f", "ВЫСОКИЙ": "#f57c00",
                      "НИЗКИЙ": "#fbc02d", "ЧИСТЫЙ": "#388e3c",
                      "НЕИЗВЕСТНО": "#9e9e9e"}
        bar_colors = [colors_map[l] for l in labels]

        if sum(sizes) > 0:
            plt.figure(figsize=(8, 6))
            bars = plt.bar(labels, sizes, color=bar_colors)
            plt.title("Распределение URL по уровням риска")
            plt.xlabel("Уровень риска"); plt.ylabel("Количество URL")
            for bar in bars:
                h = bar.get_height()
                if h > 0:
                    plt.text(bar.get_x() + bar.get_width() / 2., h,
                             f'{int(h)}', ha='center', va='bottom', fontsize=10)
            plt.tight_layout()
            chart_url_risk = os.path.join(DATA_DIR, "suricata_urls_risk_chart.png")
            plt.savefig(chart_url_risk, dpi=150); plt.close()
            print(f"[+] График рисков URL: {chart_url_risk}")
    except Exception as e:
        print(f"[!] Ошибка графиков URL: {e}")

# ============================================================
# ГРАФИКИ ПО РЕЗУЛЬТАТАМ (IP)
# ============================================================
def build_charts(suspicious_df):
    try:
        top5 = suspicious_df.nlargest(5, "dns_requests")
        plt.figure(figsize=(10, 6))
        colors = ['red' if x else 'steelblue' for x in top5["api_malicious"]]
        bars = plt.bar(top5["ip"], top5["dns_requests"], color=colors)
        plt.title("Топ-5 IP по DNS-запросам")
        plt.xlabel("IP-адрес"); plt.ylabel("DNS-запросов")
        plt.xticks(rotation=45)
        for bar in bars:
            h = bar.get_height()
            plt.text(bar.get_x()+bar.get_width()/2., h,
                     f'{int(h)}', ha='center', va='bottom', fontsize=9)
        plt.tight_layout(); plt.savefig(CHART_FILE, dpi=150); plt.close()
        print(f"[+] График топ-5 IP: {CHART_FILE}")
    except Exception as e:
        print(f"[!] Ошибка графика топ-5: {e}")

    try:
        risk_order = ["КРИТИЧЕСКИЙ", "ВЫСОКИЙ", "НИЗКИЙ", "ЧИСТЫЙ"]
        counts = {level: 0 for level in risk_order}
        for _, row in suspicious_df.iterrows():
            level = row.get("risk_level", "ЧИСТЫЙ")
            if "КРИТИЧЕСКИЙ" in level: counts["КРИТИЧЕСКИЙ"] += 1
            elif "ВЫСОКИЙ" in level:   counts["ВЫСОКИЙ"] += 1
            elif "НИЗКИЙ" in level:    counts["НИЗКИЙ"] += 1
            else:                       counts["ЧИСТЫЙ"] += 1
        labels = risk_order; sizes = [counts[l] for l in labels]
        colors_map = {"КРИТИЧЕСКИЙ": "#d32f2f", "ВЫСОКИЙ": "#f57c00",
                      "НИЗКИЙ": "#fbc02d", "ЧИСТЫЙ": "#388e3c"}
        bar_colors = [colors_map[l] for l in labels]
        plt.figure(figsize=(8, 6))
        bars = plt.bar(labels, sizes, color=bar_colors)
        plt.title("Распределение IP по уровням риска")
        plt.xlabel("Уровень риска"); plt.ylabel("Количество IP")
        for bar in bars:
            h = bar.get_height()
            plt.text(bar.get_x()+bar.get_width()/2., h,
                     f'{int(h)}', ha='center', va='bottom', fontsize=10)
        plt.tight_layout(); plt.savefig(CHART_RISK_FILE, dpi=150); plt.close()
        print(f"[+] График рисков IP: {CHART_RISK_FILE}")
    except Exception as e:
        print(f"[!] Ошибка графика рисков: {e}")

# ============================================================
# ГРАФИКИ ПО ДОМЕНАМ ИЗ ИСТОРИИ
# ============================================================
def build_history_domain_charts():
    if not os.path.exists(DB_FILE):
        return (None, None)
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT domain, MAX(total_detections) AS md
            FROM found_domains
            GROUP BY domain
            ORDER BY md DESC, domain
            LIMIT 10
        """)
        top_all = cursor.fetchall()

        cursor.execute("""
            SELECT domain, MAX(risk_level) AS lr
            FROM found_domains
            GROUP BY domain
        """)
        all_domains = cursor.fetchall()
        conn.close()

        chart_dom_1 = None
        chart_dom_2 = None

        if top_all:
            dom_names = [x[0] for x in top_all]
            det_counts = [x[1] for x in top_all]
            plt.figure(figsize=(12, 6))
            bar_colors = ['steelblue' if d == 0 else '#d32f2f' for d in det_counts]
            bars = plt.bar(dom_names, det_counts, color=bar_colors)
            plt.title("Топ-10 доменов по обнаружениям VirusTotal (все проверенные)")
            plt.xlabel("Домен"); plt.ylabel("Обнаружений")
            plt.xticks(rotation=45, ha="right")
            for bar in bars:
                h = bar.get_height()
                plt.text(bar.get_x() + bar.get_width() / 2., h,
                         f'{int(h)}', ha='center', va='bottom', fontsize=9)
            plt.tight_layout()
            chart_dom_1 = os.path.join(DATA_DIR, "history_domains_top.png")
            plt.savefig(chart_dom_1, dpi=150); plt.close()
            print(f"[+] График топ-10 доменов: {chart_dom_1}")

        if all_domains:
            risk_order = ["КРИТИЧЕСКИЙ", "ВЫСОКИЙ", "НИЗКИЙ", "ЧИСТЫЙ", "НЕИЗВЕСТНО"]
            counts = {level: 0 for level in risk_order}
            for _, level in all_domains:
                matched = False
                for key in risk_order:
                    if key in (level or ""):
                        counts[key] += 1; matched = True; break
                if not matched: counts["НЕИЗВЕСТНО"] += 1
            labels = risk_order; sizes = [counts[l] for l in labels]
            colors_map = {"КРИТИЧЕСКИЙ": "#d32f2f", "ВЫСОКИЙ": "#f57c00",
                          "НИЗКИЙ": "#fbc02d", "ЧИСТЫЙ": "#388e3c",
                          "НЕИЗВЕСТНО": "#9e9e9e"}
            bar_colors = [colors_map[l] for l in labels]
            if sum(sizes) > 0:
                plt.figure(figsize=(8, 6))
                bars = plt.bar(labels, sizes, color=bar_colors)
                plt.title("Распределение доменов по уровням риска")
                plt.xlabel("Уровень риска"); plt.ylabel("Количество доменов")
                for bar in bars:
                    h = bar.get_height()
                    if h > 0:
                        plt.text(bar.get_x() + bar.get_width() / 2., h,
                                 f'{int(h)}', ha='center', va='bottom', fontsize=10)
                plt.tight_layout()
                chart_dom_2 = os.path.join(DATA_DIR, "history_domains_risk.png")
                plt.savefig(chart_dom_2, dpi=150); plt.close()
                print(f"[+] График рисков доменов: {chart_dom_2}")
        return (chart_dom_1, chart_dom_2)
    except Exception as e:
        print(f"[!] Ошибка графиков доменов из истории: {e}")
        return (None, None)

# ============================================================
# ГРАФИКИ ПО URL ИЗ ИСТОРИИ
# ============================================================
def build_history_url_charts():
    if not os.path.exists(DB_FILE):
        return (None, None)
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT url, MAX(total_detections) AS md
            FROM found_urls
            GROUP BY url
            ORDER BY md DESC, url
            LIMIT 10
        """)
        top_all = cursor.fetchall()

        cursor.execute("""
            SELECT url, MAX(risk_level)
            FROM found_urls
            GROUP BY url
        """)
        all_urls = cursor.fetchall()
        conn.close()

        chart_url_1 = None
        chart_url_2 = None

        if top_all:
            url_names = []
            for u, _ in top_all:
                url_names.append(u[:40] + ".." if len(u) > 42 else u)
            det_counts = [x[1] for x in top_all]

            plt.figure(figsize=(12, 7))
            bar_colors = ['steelblue' if d == 0 else '#d32f2f' for d in det_counts]
            bars = plt.barh(url_names, det_counts, color=bar_colors)
            plt.title("Топ-10 URL по обнаружениям VirusTotal (все проверенные)")
            plt.xlabel("Обнаружений"); plt.ylabel("URL")
            for bar in bars:
                h = bar.get_width()
                plt.text(h, bar.get_y() + bar.get_height() / 2.,
                         f'{int(h)}', ha='left', va='center', fontsize=9)
            plt.tight_layout()
            chart_url_1 = os.path.join(DATA_DIR, "history_urls_top.png")
            plt.savefig(chart_url_1, dpi=150); plt.close()
            print(f"[+] График топ-10 URL: {chart_url_1}")

        if all_urls:
            risk_order = ["КРИТИЧЕСКИЙ", "ВЫСОКИЙ", "НИЗКИЙ", "ЧИСТЫЙ", "НЕИЗВЕСТНО"]
            counts = {level: 0 for level in risk_order}
            for _, level in all_urls:
                matched = False
                for key in risk_order:
                    if key in (level or ""):
                        counts[key] += 1; matched = True; break
                if not matched: counts["НЕИЗВЕСТНО"] += 1
            labels = risk_order; sizes = [counts[l] for l in labels]
            colors_map = {"КРИТИЧЕСКИЙ": "#d32f2f", "ВЫСОКИЙ": "#f57c00",
                          "НИЗКИЙ": "#fbc02d", "ЧИСТЫЙ": "#388e3c",
                          "НЕИЗВЕСТНО": "#9e9e9e"}
            bar_colors = [colors_map[l] for l in labels]
            if sum(sizes) > 0:
                plt.figure(figsize=(8, 6))
                bars = plt.bar(labels, sizes, color=bar_colors)
                plt.title("Распределение URL по уровням риска")
                plt.xlabel("Уровень риска"); plt.ylabel("Количество URL")
                for bar in bars:
                    h = bar.get_height()
                    if h > 0:
                        plt.text(bar.get_x() + bar.get_width() / 2., h,
                                 f'{int(h)}', ha='center', va='bottom', fontsize=10)
                plt.tight_layout()
                chart_url_2 = os.path.join(DATA_DIR, "history_urls_risk.png")
                plt.savefig(chart_url_2, dpi=150); plt.close()
                print(f"[+] График рисков URL: {chart_url_2}")
        return (chart_url_1, chart_url_2)
    except Exception as e:
        print(f"[!] Ошибка графиков URL из истории: {e}")
        return (None, None)


def build_history_charts():
    if not os.path.exists(DB_FILE):
        print("[!] База данных пуста. Сначала запустите сканирование.")
        input("   Нажмите Enter..."); return
    try:
        conn = sqlite3.connect(DB_FILE); cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, COUNT(*) AS cnt FROM found_ips WHERE blocked = 1
            GROUP BY ip ORDER BY cnt DESC LIMIT 10
        """)
        top_blocked = cursor.fetchall()
        cursor.execute("""
            SELECT SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN api_malicious = 1 AND blocked = 0 THEN 1 ELSE 0 END),
                   SUM(CASE WHEN api_malicious = 0 THEN 1 ELSE 0 END)
            FROM found_ips
        """)
        row = cursor.fetchone()
        blocked_cnt = row[0] or 0
        suspicious_cnt = row[1] or 0
        clean_cnt = row[2] or 0
        conn.close()

        chart_path_1 = os.path.join(DATA_DIR, "history_top_blocked.png")
        chart_path_2 = os.path.join(DATA_DIR, "history_status.png")

        if top_blocked:
            ips = [x[0] for x in top_blocked]; counts = [x[1] for x in top_blocked]
            plt.figure(figsize=(10, 6))
            bars = plt.bar(ips, counts, color="#d32f2f")
            plt.title("Топ-10 IP по количеству блокировок")
            plt.xlabel("IP-адрес"); plt.ylabel("Количество блокировок")
            plt.xticks(rotation=45, ha="right")
            for bar in bars:
                h = bar.get_height()
                plt.text(bar.get_x()+bar.get_width()/2., h,
                         f'{int(h)}', ha='center', va='bottom', fontsize=9)
            plt.tight_layout(); plt.savefig(chart_path_1, dpi=150); plt.close()
            print(f"[+] График топ-10 IP: {chart_path_1}")
        else:
            chart_path_1 = None
            print("[!] Нет заблокированных IP.")

        labels = ["Заблокированные", "Подозрительные", "Чистые"]
        sizes = [blocked_cnt, suspicious_cnt, clean_cnt]
        colors = ["#d32f2f", "#f57c00", "#388e3c"]
        if sum(sizes) > 0:
            plt.figure(figsize=(8, 6))
            bars = plt.bar(labels, sizes, color=colors)
            plt.title("Распределение IP по статусам")
            plt.xlabel("Статус"); plt.ylabel("Количество")
            for bar in bars:
                h = bar.get_height()
                plt.text(bar.get_x()+bar.get_width()/2., h,
                         f'{int(h)}', ha='center', va='bottom', fontsize=10)
            plt.tight_layout(); plt.savefig(chart_path_2, dpi=150); plt.close()
            print(f"[+] График статусов IP: {chart_path_2}")
        else:
            chart_path_2 = None

        print(); print(f"[+] Графики: {DATA_DIR}")

        chart_dom_1, chart_dom_2 = build_history_domain_charts()
        chart_url_1, chart_url_2 = build_history_url_charts()

        if not any([chart_path_1, chart_path_2, chart_dom_1, chart_dom_2,
                    chart_url_1, chart_url_2]):
            input("   Нажмите Enter..."); return

        print()
        print("=" * 70)
        print("   ЧТО ОТКРЫТЬ?")
        print("=" * 70)
        print("   ГРАФИКИ ПО IP:")
        print("   1. Топ-10 блокировок" if chart_path_1 else "   1. (нет данных)")
        print("   2. Распределение по статусам" if chart_path_2 else "   2. (нет данных)")
        print()
        print("   ГРАФИКИ ПО ДОМЕНАМ:")
        print("   3. Топ-10 доменов" if chart_dom_1 else "   3. (нет данных)")
        print("   4. Распределение доменов по рискам" if chart_dom_2 else "   4. (нет данных)")
        print()
        print("   ГРАФИКИ ПО URL:")
        print("   5. Топ-10 URL" if chart_url_1 else "   5. (нет данных)")
        print("   6. Распределение URL по рискам" if chart_url_2 else "   6. (нет данных)")
        print()
        print("   7. ВСЕ графики (IP + домены + URL)")
        print("   8. Открыть папку с графиками")
        print("   0. Не открывать")
        print("=" * 70)

        try: choice = input("\n   Ваш выбор (0-8): ").strip()
        except (EOFError, KeyboardInterrupt): choice = "0"

        opened = []
        if choice == "1" and chart_path_1:
            os.startfile(chart_path_1); opened.append("топ-10 IP")
        elif choice == "2" and chart_path_2:
            os.startfile(chart_path_2); opened.append("статусы IP")
        elif choice == "3" and chart_dom_1:
            os.startfile(chart_dom_1); opened.append("топ-10 доменов")
        elif choice == "4" and chart_dom_2:
            os.startfile(chart_dom_2); opened.append("риски доменов")
        elif choice == "5" and chart_url_1:
            os.startfile(chart_url_1); opened.append("топ-10 URL")
        elif choice == "6" and chart_url_2:
            os.startfile(chart_url_2); opened.append("риски URL")
        elif choice == "7":
            for p, name in [(chart_path_1, "топ-10 IP"), (chart_path_2, "статусы IP"),
                            (chart_dom_1, "топ-10 доменов"), (chart_dom_2, "риски доменов"),
                            (chart_url_1, "топ-10 URL"), (chart_url_2, "риски URL")]:
                if p:
                    os.startfile(p); opened.append(name)
        elif choice == "8":
            os.startfile(DATA_DIR); opened.append("папка")
        elif choice == "0":
            return
        else:
            print("[!] Неверный выбор."); return

        if opened:
            print(f"[+] Открыто: {', '.join(opened)}")
        input("   Нажмите Enter...")
    except Exception as e:
        print(f"[!] Ошибка графиков: {e}")
        input("   Нажмите Enter...")

# ============================================================
# ДИАЛОГ "ЧТО ОТКРЫТЬ?" ПОСЛЕ СКАНИРОВАНИЯ
# ============================================================
def open_after_scan_dialog():
    charts = [
        ("Топ-5 IP",                  CHART_FILE),
        ("Риски IP",                  CHART_RISK_FILE),
        ("Топ-10 доменов",            os.path.join(DATA_DIR, "suricata_domains_chart.png")),
        ("Риски доменов",             os.path.join(DATA_DIR, "suricata_domains_risk_chart.png")),
        ("Топ-10 URL",                os.path.join(DATA_DIR, "suricata_urls_chart.png")),
        ("Риски URL",                 os.path.join(DATA_DIR, "suricata_urls_risk_chart.png")),
    ]

    existing = [(name, path) for name, path in charts if os.path.exists(path)]

    if not existing:
        print("[i] Графики не созданы — пропускаю открытие.")
        return

    print()
    print("=" * 70)
    print("   ЧТО ОТКРЫТЬ?")
    print("=" * 70)
    for i, (name, path) in enumerate(existing, 1):
        print(f"   {i}. {name}")
    print(f"   {len(existing) + 1}. ВСЕ графики")
    print(f"   {len(existing) + 2}. Открыть папку с графиками (Проводник)")
    print("   0. Не открывать")
    print("=" * 70)

    try:
        choice = input("\n   Ваш выбор: ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "0"

    if choice == "0":
        return

    try:
        num = int(choice)
    except ValueError:
        print("[!] Неверный выбор.")
        return

    if 1 <= num <= len(existing):
        name, path = existing[num - 1]
        os.startfile(path)
        print(f"[+] Открыто: {name}")
    elif num == len(existing) + 1:
        for name, path in existing:
            os.startfile(path)
        print(f"[+] Открыто: все графики ({len(existing)} шт.)")
    elif num == len(existing) + 2:
        os.startfile(DATA_DIR)
        print(f"[+] Открыто: папка с графиками")
    else:
        print("[!] Неверный выбор.")

# ============================================================
# PENDING
# ============================================================
def load_pending():
    if not os.path.exists(PENDING_FILE):
        return {}
    try:
        with open(PENDING_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_pending(data):
    try:
        with pending_lock:
            with open(PENDING_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Ошибка сохранения pending: {e}")


def add_pending_alert(ip, risk_level, total_detections):
    data = load_pending()
    if ip in data:
        data[ip]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data[ip]["times_seen"] = data[ip].get("times_seen", 1) + 1
    else:
        data[ip] = {"ip": ip, "risk_level": risk_level,
                    "total_detections": total_detections,
                    "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "times_seen": 1, "status": "pending"}
    save_pending(data)


def is_whitelisted_or_blocked(ip):
    data = load_pending()
    if ip in data and data[ip].get("status") in ("blocked", "clean"):
        return True
    return False


def mark_pending(ip, status):
    data = load_pending()
    if ip in data:
        data[ip]["status"] = status
        data[ip]["processed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_pending(data)

# ============================================================
# ИСТОРИЯ
# ============================================================
def view_history():
    if not os.path.exists(DB_FILE):
        print("[!] База данных пуста. Запустите сканирование.")
        return
    while True:
        print()
        print("=" * 70)
        print("   ИСТОРИЯ СКАНИРОВАНИЙ")
        print("=" * 70)
        print("   1. Все сканирования (IP)")
        print("   2. Только заблокированные IP")
        print("   3. Только чистые IP")
        print("   4. Только подозрительные IP")
        print("   5. Статистика (сводка по IP)")
        print("   6. Домены (все проверенные)")
        print("   7. Домены — только опасные")
        print("   8. Домены — статистика")
        print("   9. URL (все проверенные)")
        print("  10. URL — только опасные")
        print("  11. URL — статистика")
        print("  12. Назад в главное меню")
        print("=" * 70)
        try: choice = input("\n   Что показать? (1-12): ").strip()
        except (EOFError, KeyboardInterrupt): return

        if choice == "1":   print_history("all")
        elif choice == "2": print_history("blocked")
        elif choice == "3": print_history("clean")
        elif choice == "4": print_history("suspicious")
        elif choice == "5": print_stats()
        elif choice == "6": print_domains_history("all")
        elif choice == "7": print_domains_history("malicious")
        elif choice == "8": print_domains_stats()
        elif choice == "9":  print_urls_history("all")
        elif choice == "10": print_urls_history("malicious")
        elif choice == "11": print_urls_stats()
        elif choice == "12": return
        else: print("\n[!] Неверный выбор.")


def print_history(filter_type="all"):
    try:
        conn = sqlite3.connect(DB_FILE); cursor = conn.cursor()
        cursor.execute("""
            SELECT f.ip, COUNT(*) AS total_count,
                   SUM(CASE WHEN f.blocked = 1 THEN 1 ELSE 0 END) AS blocked_count,
                   MAX(f.dns_requests) AS max_dns,
                   MAX(s.timestamp) AS last_seen,
                   f.api_malicious
            FROM found_ips f JOIN scans s ON f.scan_id = s.id
            GROUP BY f.ip
            ORDER BY blocked_count DESC, total_count DESC, f.ip
        """)
        rows = cursor.fetchall(); conn.close()
        if not rows:
            print("\n[!] История пуста."); return
        filtered = []
        for row in rows:
            ip, total, blocked_cnt, max_dns, last_seen, api_mal = row
            if filter_type == "blocked" and blocked_cnt == 0: continue
            if filter_type == "clean" and (blocked_cnt > 0 or api_mal): continue
            if filter_type == "suspicious" and not (api_mal and blocked_cnt == 0): continue
            filtered.append(row)
        if not filtered:
            print(f"\n[!] Нет записей по фильтру '{filter_type}'."); return
        titles = {"all": "ВСЕ УНИКАЛЬНЫЕ IP",
                  "blocked": "ЗАБЛОКИРОВАННЫЕ IP",
                  "clean": "ЧИСТЫЕ IP",
                  "suspicious": "ПОДОЗРИТЕЛЬНЫЕ IP"}
        print()
        print("=" * 70); print(f"   {titles.get(filter_type, 'ИСТОРИЯ')}"); print("=" * 70)
        print(f"  {'IP-адрес':<18} {'Встречался':<12} {'Блокировок':<12} {'DNS (макс)':<12} {'Последний раз':<20} {'Статус':<15}")
        print("  " + "-" * 90)
        for ip, total, blocked_cnt, max_dns, last_seen, api_mal in filtered:
            if blocked_cnt > 0: status = "ЗАБЛОКИРОВАН"
            elif api_mal:       status = "ПОДОЗРИТЕЛЬНЫЙ"
            else:               status = "ЧИСТЫЙ"
            print(f"  {ip:<18} {total:<12} {blocked_cnt:<12} {max_dns:<12} {last_seen:<20} {status:<15}")
        print("  " + "-" * 90)
        print(f"  Всего уникальных IP: {len(filtered)}"); print("=" * 70)
    except Exception as e:
        print(f"[!] Ошибка истории: {e}")


def print_stats():
    try:
        conn = sqlite3.connect(DB_FILE); cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*), COALESCE(SUM(total_suspicious), 0), COALESCE(SUM(total_blocked), 0) FROM scans")
        total_scans, total_suspicious, total_blocked = cursor.fetchone()
        cursor.execute("SELECT COUNT(DISTINCT ip) FROM found_ips")
        unique_ips = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT ip) FROM found_ips WHERE blocked = 1")
        unique_blocked = cursor.fetchone()[0]
        cursor.execute("SELECT ip, COUNT(*) as c FROM found_ips WHERE blocked = 1 GROUP BY ip ORDER BY c DESC LIMIT 5")
        top_blocked = cursor.fetchall()
        conn.close()
        print()
        print("=" * 70); print("   СТАТИСТИКА ПО ВСЕЙ ИСТОРИИ (IP)"); print("=" * 70)
        print(f"  Всего сканирований:        {total_scans}")
        print(f"  Всего найдено IP:          {total_suspicious}")
        print(f"  Всего блокировок:          {total_blocked}")
        print(f"  Уникальных IP:             {unique_ips}")
        print(f"  Уникальных заблокированных: {unique_blocked}")
        if top_blocked:
            print(); print("  ТОП-5 IP по количеству блокировок:")
            print("  " + "-" * 66)
            for ip, cnt in top_blocked:
                print(f"    {ip:<18} — заблокирован {cnt} раз(а)")
            print("  " + "-" * 66)
        print("=" * 70)
    except Exception as e:
        print(f"[!] Ошибка статистики: {e}")


def print_domains_history(filter_type="all"):
    try:
        conn = sqlite3.connect(DB_FILE); cursor = conn.cursor()
        cursor.execute("""
            SELECT d.domain, COUNT(*) AS total_count,
                   MAX(d.risk_level) AS last_risk,
                   MAX(d.total_detections) AS max_det,
                   MAX(s.timestamp) AS last_seen,
                   SUM(CASE WHEN d.malicious = 1 THEN 1 ELSE 0 END) AS mal_count
            FROM found_domains d JOIN scans s ON d.scan_id = s.id
            GROUP BY d.domain
            ORDER BY mal_count DESC, max_det DESC, d.domain
        """)
        rows = cursor.fetchall(); conn.close()
        if not rows:
            print("\n[!] История доменов пуста."); return
        filtered = [r for r in rows if not (filter_type == "malicious" and r[5] == 0)]
        if not filtered:
            print(f"\n[!] Нет доменов по фильтру '{filter_type}'."); return
        title = "ВСЕ ПРОВЕРЕННЫЕ ДОМЕНЫ" if filter_type == "all" else "ОПАСНЫЕ ДОМЕНЫ"
        print()
        print("=" * 70); print(f"   {title}"); print("=" * 70)
        print(f"  {'Домен':<40} {'Проверок':<10} {'Обнар.':<8} {'Последний раз':<20} {'Риск':<15}")
        print("  " + "-" * 95)
        for domain, total, last_risk, max_det, last_seen, mal_count in filtered:
            d = domain[:38] + ".." if len(domain) > 40 else domain
            print(f"  {d:<40} {total:<10} {max_det:<8} {last_seen:<20} {last_risk:<15}")
        print("  " + "-" * 95); print(f"  Всего доменов: {len(filtered)}"); print("=" * 70)
    except Exception as e:
        print(f"[!] Ошибка истории доменов: {e}")


def print_domains_stats():
    try:
        conn = sqlite3.connect(DB_FILE); cursor = conn.cursor()
        cursor.execute("SELECT COUNT(DISTINCT domain) FROM found_domains")
        unique_domains = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT domain) FROM found_domains WHERE malicious = 1")
        unique_malicious = cursor.fetchone()[0]
        cursor.execute("SELECT risk_level, COUNT(*) FROM found_domains GROUP BY risk_level ORDER BY COUNT(*) DESC")
        risk_rows = cursor.fetchall()
        cursor.execute("""
            SELECT domain, MAX(total_detections) AS md FROM found_domains
            WHERE total_detections > 0 GROUP BY domain ORDER BY md DESC LIMIT 5
        """)
        top_bad = cursor.fetchall()
        conn.close()
        print()
        print("=" * 70); print("   СТАТИСТИКА ПО ДОМЕНАМ"); print("=" * 70)
        print(f"  Уникальных доменов:        {unique_domains}")
        print(f"  Уникальных опасных доменов:{unique_malicious}")
        if risk_rows:
            print(); print("  Распределение по уровням риска:")
            print("  " + "-" * 66)
            for level, cnt in risk_rows:
                print(f"    {level:<25} — {cnt} домен(ов)")
            print("  " + "-" * 66)
        if top_bad:
            print(); print("  ТОП-5 доменов по обнаружениям:")
            print("  " + "-" * 66)
            for domain, md in top_bad:
                print(f"    {domain:<45} — {md} обнаружений")
            print("  " + "-" * 66)
        print("=" * 70)
    except Exception as e:
        print(f"[!] Ошибка статистики доменов: {e}")


def print_urls_history(filter_type="all"):
    try:
        conn = sqlite3.connect(DB_FILE); cursor = conn.cursor()
        cursor.execute("""
            SELECT u.url, COUNT(*) AS total_count,
                   MAX(u.risk_level) AS last_risk,
                   MAX(u.total_detections) AS max_det,
                   MAX(s.timestamp) AS last_seen,
                   SUM(CASE WHEN u.malicious = 1 THEN 1 ELSE 0 END) AS mal_count
            FROM found_urls u JOIN scans s ON u.scan_id = s.id
            GROUP BY u.url
            ORDER BY mal_count DESC, max_det DESC, u.url
        """)
        rows = cursor.fetchall(); conn.close()
        if not rows:
            print("\n[!] История URL пуста."); return
        filtered = [r for r in rows if not (filter_type == "malicious" and r[5] == 0)]
        if not filtered:
            print(f"\n[!] Нет URL по фильтру '{filter_type}'."); return
        title = "ВСЕ ПРОВЕРЕННЫЕ URL" if filter_type == "all" else "ОПАСНЫЕ URL"
        print()
        print("=" * 70); print(f"   {title}"); print("=" * 70)
        print(f"  {'URL':<55} {'Проверок':<10} {'Обнар.':<8} {'Риск':<15}")
        print("  " + "-" * 95)
        for url, total, last_risk, max_det, last_seen, mal_count in filtered:
            u = url[:53] + ".." if len(url) > 55 else url
            print(f"  {u:<55} {total:<10} {max_det:<8} {last_risk:<15}")
        print("  " + "-" * 95); print(f"  Всего URL: {len(filtered)}"); print("=" * 70)
    except Exception as e:
        print(f"[!] Ошибка истории URL: {e}")


def print_urls_stats():
    try:
        conn = sqlite3.connect(DB_FILE); cursor = conn.cursor()
        cursor.execute("SELECT COUNT(DISTINCT url) FROM found_urls")
        unique_urls = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT url) FROM found_urls WHERE malicious = 1")
        unique_malicious = cursor.fetchone()[0]
        cursor.execute("SELECT risk_level, COUNT(*) FROM found_urls GROUP BY risk_level ORDER BY COUNT(*) DESC")
        risk_rows = cursor.fetchall()
        cursor.execute("""
            SELECT url, MAX(total_detections) AS md FROM found_urls
            WHERE total_detections > 0 GROUP BY url ORDER BY md DESC LIMIT 5
        """)
        top_bad = cursor.fetchall()
        conn.close()
        print()
        print("=" * 70); print("   СТАТИСТИКА ПО URL"); print("=" * 70)
        print(f"  Уникальных URL:            {unique_urls}")
        print(f"  Уникальных опасных URL:    {unique_malicious}")
        if risk_rows:
            print(); print("  Распределение по уровням риска:")
            print("  " + "-" * 66)
            for level, cnt in risk_rows:
                print(f"    {level:<25} — {cnt} URL")
            print("  " + "-" * 66)
        if top_bad:
            print(); print("  ТОП-5 URL по обнаружениям:")
            print("  " + "-" * 66)
            for url, md in top_bad:
                u = url[:50] + ".." if len(url) > 52 else url
                print(f"    {u:<55} — {md}")
            print("  " + "-" * 66)
        print("=" * 70)
    except Exception as e:
        print(f"[!] Ошибка статистики URL: {e}")

# ============================================================
# РУЧНАЯ ПРОВЕРКА — IP, ДОМЕН или URL
# ============================================================
def manual_check():
    print()
    print("=" * 70); print("   РУЧНАЯ ПРОВЕРКА"); print("=" * 70)
    print("   Можно ввести IP-адрес, домен или URL.")
    print("   Примеры: 8.8.8.8 | google.com | http://example.com/page")
    print("-" * 70)
    target = input("   Введите IP, домен или URL: ").strip()
    if not target:
        print("\n   [!] Пустой ввод."); return

    is_ip = False
    is_url = target.startswith("http://") or target.startswith("https://") or "/" in target

    if not is_url:
        parts = target.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            is_ip = True

    print()
    if is_url:
        print(f"   [i] Распознан URL: {target}")
        result = check_url_virustotal(target)
        target_type = "URL"
    elif is_ip:
        print(f"   [i] Распознан IP-адрес: {target}")
        result = check_ip_virustotal(target)
        target_type = "IP"
    else:
        print(f"   [i] Распознан домен: {target}")
        result = check_domain_virustotal(target)
        target_type = "ДОМЕН"

    print(); print("-" * 70)
    risk_level = result.get("risk_level", "НЕИЗВЕСТНО")
    if risk_level in ("НЕТ ДАННЫХ", "ОШИБКА", "ТАЙМАУТ", "НЕИЗВЕСТНО",
                      "НЕ НАСТРОЕН", "НЕ АВТОРИЗОВАН"):
        print(f"   [?] {target_type} {target} — {risk_level}")
        print(f"       Источник: {result['source']}")
        print("-" * 70); return

    if result.get("malicious"):
        print(f"   [!] {target_type} {target} — ВРЕДОНОСНЫЙ")
        print(f"       Уровень риска: {result['risk_level']}")
        print(f"       Обнаружений: {result.get('total_detections', 0)}")
        print(f"       Источник: {result['source']}")
        print("-" * 70)

        if is_ip:
            print()
            answer = input(f"   Заблокировать IP {target}? (y/n): ").strip().lower()
            if answer in ("y", "yes", "д", "да"):
                print()
                print("!" * 70)
                print(f"   [BLOCK] Имитация блокировки IP {target}...")
                print("!" * 70)
                try:
                    winsound.Beep(1000, 400); time.sleep(0.15)
                    winsound.Beep(1500, 400); time.sleep(0.15)
                    winsound.Beep(2000, 400)
                except Exception: pass
                try:
                    show_popup("IP ЗАБЛОКИРОВАН",
                               f"IP-адрес: {target}\n\nУровень риска: {result['risk_level']}")
                except Exception: pass
                notify_all(ip=target, risk_level=result["risk_level"],
                           total_detections=result.get("total_detections", 0),
                           source="Ручная проверка")
                report_data = [{"ip": target, "dns_requests": 1, "api_malicious": True,
                                "risk_level": result["risk_level"],
                                "total_detections": result.get("total_detections", 0),
                                "blocked": True}]
                save_scan_to_db(report_data, [target], 0)
            else:
                print(f"\n   [+] IP {target} не заблокирован.")
        else:
            print()
            print(f"   [i] {target_type} {target} — только предупреждение.")
            print(f"       Блокировка {target_type} в этой версии не поддерживается.")
    else:
        print(f"   [+] {target_type} {target} — ЧИСТЫЙ")
        print(f"       Уровень риска: {result['risk_level']}")
        print(f"       Обнаружений: {result.get('total_detections', 0)}")
        print(f"       Источник: {result['source']}")
    print("-" * 70)

# ============================================================
# ПАКЕТНОЕ СКАНИРОВАНИЕ
# ============================================================
def run_scan():
    global LAST_DOMAINS, LAST_URLS
    LAST_DOMAINS = []
    LAST_URLS = []

    print()
    print("=" * 70); print("   ЗАПУСК НОВОГО СКАНИРОВАНИЯ"); print("=" * 70)

    if VT_MODE == "fake":
        print("[*] Режим ИМИТАЦИИ: Suricata НЕ запускается.")
        print(f"[*] Источник данных: {FAKE_GENERATED_FILE if os.path.exists(FAKE_GENERATED_FILE) else IP_LIST_FILE}")
    else:
        process = start_suricata()
        if process is None: return
        print(f"[*] Сбор трафика {CAPTURE_SECONDS} сек...")
        print("[*] Откройте сайты в браузере!")
        time.sleep(CAPTURE_SECONDS)
        stop_suricata(process)

    print(); print("[*] Анализ данных...")
    df_logs = analyze_eve(EVE_FILE)
    if df_logs.empty:
        print("[!] Данные не собраны."); return

    suspicious_df = df_logs[df_logs["dns_requests"] >= DNS_THRESHOLD].copy()

    # ← ИЗМЕНЕНО: если IP не найдено — всё равно проверяем домены и URL, строим графики
    if suspicious_df.empty:
        print("[!] Подозрительных IP не найдено — проверяю домены и URL.")

        # --- проверка доменов ---
        if LAST_DOMAINS:
            print(); print("-" * 70)
            print("   ПРОВЕРКА ДОМЕНОВ ЧЕРЕЗ VIRUSTOTAL")
            print("-" * 70)
            for idx, domain in enumerate(LAST_DOMAINS):
                if domain in TRUSTED_DOMAINS:
                    print(f"  [+] {domain} — ЧИСТЫЙ (из белого списка)")
                    continue
                result = check_domain_virustotal(domain)
                if result.get("malicious"):
                    print(f"  [!] ОПАСНЫЙ ДОМЕН: {domain} "
                          f"(Уровень: {result['risk_level']}, Обнаружений: {result['total_detections']})")
                else:
                    print(f"  [+] {domain} — {result.get('risk_level', 'НЕИЗВЕСТНО')}")
                if VT_MODE != "fake" and idx < len(LAST_DOMAINS) - 1:
                    print("  [*] Пауза 15 сек (лимит API)...")
                    time.sleep(15)
            print("-" * 70)
        else:
            print(); print("[i] Домены не найдены — проверка доменов пропущена.")

        # --- проверка URL ---
        if LAST_URLS:
            print(); print("-" * 70)
            print("   ПРОВЕРКА URL ЧЕРЕЗ VIRUSTOTAL")
            print("-" * 70)
            for idx, url in enumerate(LAST_URLS):
                hostname = urlparse(url).hostname or ""
                trusted = any(hostname.endswith(td) for td in TRUSTED_DOMAINS)
                if trusted:
                    print(f"  [+] {url} — ЧИСТЫЙ (из белого списка)")
                    URL_CACHE[url] = {"url": url, "malicious": False,
                                      "total_detections": 0,
                                      "risk_level": "ЧИСТЫЙ",
                                      "source": "Whitelisted"}
                    continue
                result = check_url_virustotal(url)
                if result.get("malicious"):
                    print(f"  [!] ОПАСНЫЙ URL: {url} "
                          f"(Уровень: {result['risk_level']}, Обнаружений: {result['total_detections']})")
                else:
                    print(f"  [+] {url} — {result.get('risk_level', 'НЕИЗВЕСТНО')}")
                if VT_MODE != "fake" and idx < len(LAST_URLS) - 1:
                    print("  [*] Пауза 15 сек (лимит API)...")
                    time.sleep(15)
            print("-" * 70)
        else:
            print(); print("[i] URL не найдены — проверка URL пропущена.")

        # --- сохраняем и строим графики доменов и URL ---
        save_domains_to_db(LAST_DOMAINS, DOMAIN_CACHE)
        save_urls_to_db(LAST_URLS, URL_CACHE)

        build_domain_charts(LAST_DOMAINS, DOMAIN_CACHE)
        build_url_charts(LAST_URLS, URL_CACHE)

        open_after_scan_dialog()
        return

    print(f"[+] Найдено {len(suspicious_df)} подозрительных IP."); print()

    api_results, risk_levels, detection_counts = [], [], []
    for i, ip in enumerate(suspicious_df["ip"]):
        res = check_ip_virustotal(ip)
        api_results.append(res["malicious"])
        risk_levels.append(res.get("risk_level", "НЕИЗВЕСТНО"))
        detection_counts.append(res.get("total_detections", 0))
        if VT_MODE != "fake" and i < len(suspicious_df) - 1:
            print("  [*] Пауза 16 сек (лимит API)...")
            time.sleep(16)

    suspicious_df["api_malicious"] = api_results
    suspicious_df["risk_level"] = risk_levels
    suspicious_df["total_detections"] = detection_counts

    print(); print("-" * 70)
    print("   РЕАГИРОВАНИЕ НА УГРОЗЫ (IP)")
    print("-" * 70)
    blocked_ips = []
    for _, row in suspicious_df.iterrows():
        ip = row["ip"]
        if row["api_malicious"]:
            print(f"  [!] УГРОЗА: IP {ip} (DNS: {row['dns_requests']}, Уровень: {row['risk_level']})")
            print(f"      [BLOCK] Имитация блокировки...")
            blocked_ips.append(ip)
            notify_all(ip=ip, risk_level=row["risk_level"],
                       total_detections=row["total_detections"],
                       source=f"Пакетное сканирование (DNS: {row['dns_requests']})")
        else:
            print(f"  [?] IP {ip} — ниже порога.")
    if not blocked_ips: print("  [+] Критических угроз не найдено.")
    print("-" * 70)

    # --- проверка доменов ---
    if LAST_DOMAINS:
        print(); print("-" * 70)
        print("   ПРОВЕРКА ДОМЕНОВ ЧЕРЕЗ VIRUSTOTAL")
        print("-" * 70)
        for idx, domain in enumerate(LAST_DOMAINS):
            if domain in TRUSTED_DOMAINS:
                print(f"  [+] {domain} — ЧИСТЫЙ (из белого списка)")
                continue
            result = check_domain_virustotal(domain)
            if result.get("malicious"):
                print(f"  [!] ОПАСНЫЙ ДОМЕН: {domain} "
                      f"(Уровень: {result['risk_level']}, Обнаружений: {result['total_detections']})")
            else:
                print(f"  [+] {domain} — {result.get('risk_level', 'НЕИЗВЕСТНО')}")
            if VT_MODE != "fake" and idx < len(LAST_DOMAINS) - 1:
                print("  [*] Пауза 15 сек (лимит API)...")
                time.sleep(15)
        print("-" * 70)
    else:
        print(); print("[i] Домены не найдены — проверка доменов пропущена.")

    # проверка URL
    if LAST_URLS:
        print(); print("-" * 70)
        print("   ПРОВЕРКА URL ЧЕРЕЗ VIRUSTOTAL")
        print("-" * 70)
        for idx, url in enumerate(LAST_URLS):
            hostname = urlparse(url).hostname or ""
            trusted = any(hostname.endswith(td) for td in TRUSTED_DOMAINS)
            if trusted:
                print(f"  [+] {url} — ЧИСТЫЙ (из белого списка)")
                URL_CACHE[url] = {"url": url, "malicious": False,
                                  "total_detections": 0,
                                  "risk_level": "ЧИСТЫЙ",
                                  "source": "Whitelisted"}
                continue

            result = check_url_virustotal(url)
            if result.get("malicious"):
                print(f"  [!] ОПАСНЫЙ URL: {url} "
                      f"(Уровень: {result['risk_level']}, Обнаружений: {result['total_detections']})")
            else:
                print(f"  [+] {url} — {result.get('risk_level', 'НЕИЗВЕСТНО')}")
            if VT_MODE != "fake" and idx < len(LAST_URLS) - 1:
                print("  [*] Пауза 15 сек (лимит API)...")
                time.sleep(15)
        print("-" * 70)
    else:
        print(); print("[i] URL не найдены — проверка URL пропущена.")

    # --- сохранение отчёта ---
    report_data = suspicious_df.to_dict(orient="records")
    for item in report_data:
        item["blocked"] = item["ip"] in blocked_ips

    final_report = {
        "summary": {
            "total_suspicious": len(suspicious_df),
            "total_blocked": len(blocked_ips),
            "total_domains": len(LAST_DOMAINS),
            "total_urls": len(LAST_URLS),
            "capture_time_sec": CAPTURE_SECONDS,
            "threshold_used": MALICIOUS_THRESHOLD,
            "vt_mode": VT_MODE,
        },
        "details": report_data,
        "domains_checked": LAST_DOMAINS,
        "urls_checked": LAST_URLS,
    }
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=4, ensure_ascii=False)
    print(); print(f"[+] Отчет сохранен: {REPORT_FILE}")

    save_scan_to_db(report_data, blocked_ips, CAPTURE_SECONDS)
    save_domains_to_db(LAST_DOMAINS, DOMAIN_CACHE)
    save_urls_to_db(LAST_URLS, URL_CACHE)

    build_charts(suspicious_df)
    build_domain_charts(LAST_DOMAINS, DOMAIN_CACHE)
    build_url_charts(LAST_URLS, URL_CACHE)

    open_after_scan_dialog()

# ============================================================
# ФОНОВЫЙ МОНИТОРИНГ
# ============================================================
def realtime_monitor():
    print()
    print("=" * 70); print("   ЗАПУСК ФОНОВОГО МОНИТОРИНГА"); print("=" * 70)
    print(); print("[*] Открываю мониторинг в отдельном (свёрнутом) окне..."); print()
    try:
        if getattr(sys, 'frozen', False):
            args = [sys.executable, "--monitor-worker", "--vt-mode", VT_MODE]
        else:
            script_path = os.path.abspath(__file__)
            args = [sys.executable, script_path, "--monitor-worker", "--vt-mode", VT_MODE]
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 7
        process = subprocess.Popen(args, creationflags=subprocess.CREATE_NEW_CONSOLE,
                                   startupinfo=startupinfo)
        print(f"[+] Мониторинг запущен в фоне. PID: {process.pid}")
        print(f"[*] Режим VirusTotal: {'ИМИТАЦИЯ' if VT_MODE == 'fake' else 'РЕАЛЬНЫЙ API'}")
        print(f"[*] Логи: {MONITOR_LOG_FILE}")
        print("[*] Для остановки — открой свёрнутое окно и нажми Ctrl+C.")
        print(); print("=" * 70)
        try: input("   Нажмите Enter, чтобы вернуться в меню...")
        except (EOFError, KeyboardInterrupt): pass
    except Exception as e:
        print(f"[!] Не удалось запустить: {e}")
        try: input("   Нажмите Enter...")
        except (EOFError, KeyboardInterrupt): pass


def realtime_monitor_worker():
    global USER_CONFIG, VT_MODE
    if VT_MODE not in ("real", "fake"):
        USER_CONFIG = load_user_config() or DEFAULT_USER_CONFIG.copy()
        VT_MODE = USER_CONFIG.get("vt_mode", "real")
    USER_CONFIG = load_user_config() or DEFAULT_USER_CONFIG.copy()
    log_file = open(MONITOR_LOG_FILE, "a", encoding="utf-8")

    def log(msg):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        try: print(line)
        except Exception: pass
        try:
            log_file.write(line + "\n"); log_file.flush()
        except Exception: pass

    log("=" * 70); log("   ФОНОВЫЙ МОНИТОРИНГ ЗАПУЩЕН"); log("=" * 70)
    log(f"Режим VirusTotal: {'ИМИТАЦИЯ' if VT_MODE == 'fake' else 'РЕАЛЬНЫЙ API'}")

    if VT_MODE == "fake":
        log("[*] Режим ИМИТАЦИИ: Suricata не запускается.")
        log(f"[*] Файл событий: {FAKE_GENERATED_FILE if os.path.exists(FAKE_GENERATED_FILE) else IP_LIST_FILE}")
        log("[*] Цикл: проверка файла → пауза 30 сек → снова.")
        seen_ips = set(); alerts_count = 0
        try:
            while True:
                try:
                    src_file = FAKE_GENERATED_FILE if os.path.exists(FAKE_GENERATED_FILE) else IP_LIST_FILE
                    if not os.path.exists(src_file):
                        create_default_ip_list_file(); src_file = IP_LIST_FILE
                    with open(src_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    dns_events = data.get("dns_events", [])
                except Exception as e:
                    log(f"[!] Ошибка чтения: {e}"); dns_events = []

                log(""); log("-" * 70)
                log(f"[*] Проверка файла: событий {len(dns_events)}, уже видел IP: {len(seen_ips)}")
                log("-" * 70)

                new_checked = 0
                for ev in dns_events:
                    src_ip = str(ev.get("src_ip", "")).strip()
                    if not src_ip or src_ip in seen_ips: continue
                    seen_ips.add(src_ip); new_checked += 1
                    log(""); log(f"[>] НОВЫЙ IP: {src_ip}")
                    try: result = check_ip_virustotal(src_ip)
                    except Exception as e: log(f"    [!] Ошибка: {e}"); continue
                    if result.get("malicious", False):
                        alerts_count += 1
                        log("!" * 70); log(f"!!! УГРОЗА #{alerts_count} !!!")
                        log(f"IP: {src_ip}"); log(f"Уровень: {result['risk_level']}")
                        log(f"Обнаружений: {result['total_detections']}"); log("!" * 70)
                        add_pending_alert(src_ip, result['risk_level'], result['total_detections'])
                        notify_all(ip=src_ip, risk_level=result['risk_level'],
                                   total_detections=result['total_detections'],
                                   source="Фоновый мониторинг (имитация)")
                        try:
                            winsound.Beep(1000, 400); time.sleep(0.15)
                            winsound.Beep(1500, 400); time.sleep(0.15)
                            winsound.Beep(2000, 400)
                        except Exception: pass
                    else:
                        log(f"    [+] IP {src_ip} — {result.get('risk_level', 'НЕИЗВЕСТНО')}")
                if new_checked == 0:
                    log(""); log("  [~] Новых IP нет. Жду 30 секунд...")
                log(""); log("[*] Пауза 30 секунд... (Ctrl+C для остановки)")
                for remaining in range(30, 0, -1):
                    ts = datetime.now().strftime("%H:%M:%S")
                    line2 = f"[{ts}]   ⏳ Следующая проверка через: {remaining} сек..."
                    try: print(line2)
                    except Exception: pass
                    try: log_file.write(line2 + "\n"); log_file.flush()
                    except Exception: pass
                    time.sleep(1)
        except KeyboardInterrupt:
            log(""); log("[*] Остановка по Ctrl+C.")
            log(f"[+] Проверено уникальных IP: {len(seen_ips)}"); log(f"[+] Тревог: {alerts_count}")
            log("=" * 70)
        log_file.close()
        print(); print("=" * 70); print("   МОНИТОРИНГ ОСТАНОВЛЕН")
        print(f"   Проверено IP: {len(seen_ips)} | Тревог: {alerts_count}")
        print("=" * 70); print()
        input("   Нажмите Enter, чтобы закрыть окно...")
        return

    # РЕАЛЬНЫЙ РЕЖИМ
    process = start_suricata()
    if process is None:
        log("[!] Не удалось запустить Suricata.")
        log_file.close(); input("   Нажмите Enter..."); return
    if os.path.exists(EVE_FILE):
        try:
            with open(EVE_FILE, "w", encoding="utf-8") as f: f.write("")
        except Exception as e: log(f"[!] Не удалось очистить eve.json: {e}")
    log("Мониторинг запущен."); log("-" * 70)

    checked_ips = {}; alerts_count = 0; total_checked = 0
    start_time = time.time(); last_heartbeat = time.time(); last_idle_notify = time.time()
    HEARTBEAT_INTERVAL = 60; IDLE_NOTIFY_INTERVAL = 30; API_PAUSE = 16
    try:
        wait_time = 0
        while not os.path.exists(EVE_FILE) and wait_time < 10:
            time.sleep(0.5); wait_time += 0.5
        if not os.path.exists(EVE_FILE):
            log("[!] eve.json не создан."); stop_suricata(process)
            log_file.close(); input("   Нажмите Enter..."); return
        with open(EVE_FILE, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)
            while True:
                try:
                    now = time.time()
                    if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                        elapsed = int(now - start_time); m, s = elapsed // 60, elapsed % 60
                        log(""); log(f"  [♥] Работаю {m:02d}:{s:02d} | Проверено: {total_checked} | Тревог: {alerts_count}"); log("")
                        last_heartbeat = now; last_idle_notify = now
                    line = f.readline()
                    if not line:
                        if now - last_idle_notify >= IDLE_NOTIFY_INTERVAL:
                            log("  [~] Жду новых DNS-событий..."); last_idle_notify = now
                        time.sleep(0.5); continue
                    try: event = json.loads(line)
                    except json.JSONDecodeError: continue
                    if event.get("event_type") != "dns": continue
                    src_ip = event.get("src_ip")
                    if not src_ip: continue
                    if src_ip in checked_ips and (now - checked_ips[src_ip]) < REALTIME_CACHE_TIMEOUT: continue
                    if is_whitelisted_or_blocked(src_ip): continue
                    checked_ips[src_ip] = now; total_checked += 1; last_idle_notify = now
                    log(""); log(f"[>] Новый IP: {src_ip}. Проверка...")
                    try: result = check_ip_virustotal(src_ip)
                    except Exception as e:
                        log(f"    [!] Ошибка: {e}"); time.sleep(5); continue
                    if result.get("malicious", False):
                        alerts_count += 1
                        log(""); log("!" * 70); log(f"!!! УГРОЗА #{alerts_count} !!!")
                        log(f"IP: {src_ip}"); log(f"Уровень: {result['risk_level']}")
                        log(f"Обнаружений: {result['total_detections']}"); log("!" * 70); log("")
                        add_pending_alert(src_ip, result['risk_level'], result['total_detections'])
                        notify_all(ip=src_ip, risk_level=result['risk_level'],
                                   total_detections=result['total_detections'],
                                   source="Фоновый мониторинг")
                        report_data = [{"ip": src_ip, "dns_requests": 1,
                                        "api_malicious": True,
                                        "risk_level": result['risk_level'],
                                        "total_detections": result['total_detections'],
                                        "blocked": True}]
                        save_scan_to_db(report_data, [src_ip], 0)
                        try:
                            winsound.Beep(1000, 400); time.sleep(0.15)
                            winsound.Beep(1500, 400); time.sleep(0.15)
                            winsound.Beep(2000, 400)
                        except Exception: pass
                        pending = load_pending()
                        if pending.get(src_ip, {}).get("times_seen", 1) == 1:
                            try:
                                show_popup("ТРЕВОГА!",
                                           f"Вредоносный IP: {src_ip}\n\nУровень: {result['risk_level']}")
                            except Exception as e: log(f"    [!] Ошибка окна: {e}")
                    else:
                        log(f"    [+] IP {src_ip} — {result.get('risk_level', 'НЕИЗВЕСТНО')}")
                    if API_PAUSE > 0:
                        log(""); log(f"    [*] Пауза {API_PAUSE} сек...")
                        for remaining in range(API_PAUSE, 0, -1):
                            ts = datetime.now().strftime("%H:%M:%S")
                            line2 = f"[{ts}]   ⏳ До следующей проверки: {remaining} сек..."
                            try: print(line2)
                            except Exception: pass
                            try: log_file.write(line2 + "\n"); log_file.flush()
                            except Exception: pass
                            time.sleep(1)
                    last_idle_notify = time.time(); log("")
                except Exception as loop_error:
                    log(f"[!] Ошибка в цикле: {loop_error}"); time.sleep(5); continue
    except KeyboardInterrupt:
        log(""); log("[*] Остановка по Ctrl+C...")
    finally:
        stop_suricata(process)
        elapsed = int(time.time() - start_time); m, s = elapsed // 60, elapsed % 60
        log(""); log("[+] Мониторинг остановлен.")
        log(f"[+] Время: {m:02d}:{s:02d}")
        log(f"[+] Проверено IP: {total_checked}"); log(f"[+] Тревог: {alerts_count}")
        log("=" * 70); log_file.close()
        print(); print("=" * 70); print("   МОНИТОРИНГ ОСТАНОВЛЕН")
        print(f"   Время: {m:02d}:{s:02d} | Проверено: {total_checked} | Тревог: {alerts_count}")
        print("=" * 70); print()
        input("   Нажмите Enter, чтобы закрыть окно...")

# ============================================================
# УВЕДОМЛЕНИЯ ОБ УГРОЗАХ
# ============================================================
def check_pending_alerts():
    while True:
        data = load_pending()
        pending = {ip: info for ip, info in data.items() if info.get("status") == "pending"}
        print(); print("=" * 70); print("   НЕПОДТВЕРЖДЁННЫЕ УГРОЗЫ"); print("=" * 70)
        if not pending:
            print("\n   [+] Нет неподтверждённых угроз.")
            print("=" * 70); input("   Нажмите Enter..."); return
        print()
        print(f"  {'#':<4} {'IP-адрес':<18} {'Риск':<25} {'Обнар.':<8} {'Видел раз':<10} {'Последний раз':<20}")
        print("  " + "-" * 90)
        ip_list = list(pending.keys())
        for i, ip in enumerate(ip_list, 1):
            info = pending[ip]
            print(f"  {i:<4} {ip:<18} {info['risk_level']:<25} "
                  f"{info['total_detections']:<8} {info['times_seen']:<10} {info['last_seen']:<20}")
        print("  " + "-" * 90)
        print(); print("   <номер> — выбрать IP"); print("   all — обработать все"); print("   0 — выйти"); print()
        choice = input("   Ваш выбор: ").strip().lower()
        if choice == "0": return
        elif choice == "all":
            action = input("   Действие для ВСЕХ (b = блокировать, c = чистый): ").strip().lower()
            if action in ("b", "c"):
                status = "blocked" if action == "b" else "clean"
                for ip in ip_list:
                    mark_pending(ip, status)
                    if status == "blocked":
                        report_data = [{"ip": ip, "dns_requests": 1, "api_malicious": True,
                                        "risk_level": pending[ip]["risk_level"],
                                        "total_detections": pending[ip]["total_detections"],
                                        "blocked": True}]
                        save_scan_to_db(report_data, [ip], 0)
                print(f"\n   [+] Все {len(ip_list)} IP помечены как {status.upper()}.")
                input("   Enter...")
        else:
            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(ip_list):
                    print("\n   [!] Неверный номер."); input("   Enter..."); continue
                ip = ip_list[idx]; info = pending[ip]
                print(); print(f"   IP: {ip}")
                print(f"   Уровень риска: {info['risk_level']}")
                print(f"   Обнаружений: {info['total_detections']}")
                print(f"   Встречался раз: {info['times_seen']}"); print()
                action = input("   Действие (b = блокировать, c = чистый, 0 = отмена): ").strip().lower()
                if action == "b":
                    mark_pending(ip, "blocked")
                    report_data = [{"ip": ip, "dns_requests": 1, "api_malicious": True,
                                    "risk_level": info["risk_level"],
                                    "total_detections": info["total_detections"],
                                    "blocked": True}]
                    save_scan_to_db(report_data, [ip], 0)
                    print(f"\n   [+] IP {ip} ЗАБЛОКИРОВАН.")
                elif action == "c":
                    mark_pending(ip, "clean")
                    print(f"\n   [+] IP {ip} помечен как ЧИСТЫЙ.")
                input("   Enter...")
            except ValueError:
                print("\n   [!] Неверный ввод."); input("   Enter...")

# ============================================================
# НАСТРОЙКИ УВЕДОМЛЕНИЙ
# ============================================================
def edit_notification_settings():
    global USER_CONFIG
    while True:
        cfg = USER_CONFIG or load_user_config() or DEFAULT_USER_CONFIG.copy()
        pname = EMAIL_PRESETS.get(cfg.get("email_provider", ""), {}).get("name", "—")
        key_status = "задан" if cfg.get("vt_api_key") else "(не задан)"
        print(); print("=" * 70); print("   НАСТРОЙКИ УВЕДОМЛЕНИЙ"); print("=" * 70)
        print(f"   Файл настроек: {USER_CONFIG_FILE}"); print()
        print(f"   0. API-ключ VirusTotal: {key_status}"); print()
        print(f"   1. Email включён:    {'ДА' if cfg.get('email_enabled') else 'НЕТ'}")
        print(f"      Сервис:           {pname}")
        print(f"      SMTP:             {cfg.get('email_smtp_host')}:{cfg.get('email_smtp_port')}")
        print(f"      От:               {cfg.get('email_from') or '(не задано)'}")
        print(f"      Кому:             {cfg.get('email_to') or '(не задано)'}")
        print(f"      Пароль:           {'*' * len(cfg.get('email_app_pass', '')) if cfg.get('email_app_pass') else '(не задан)'}")
        print()
        print(f"   2. Telegram включён: {'ДА' if cfg.get('telegram_enabled') else 'НЕТ'}")
        print(f"      Bot Token:        {cfg.get('telegram_bot_token')[:12] + '...' if cfg.get('telegram_bot_token') else '(не задан)'}")
        print(f"      Chat ID:          {cfg.get('telegram_chat_id') or '(не задан)'}")
        print()
        print("   3. Включить/выключить Email"); print("   4. Включить/выключить Telegram")
        print("   5. Изменить Email-настройки (адреса)")
        print("   6. Сменить почтовый сервис")
        print("   7. Ввести/сменить пароль приложения")
        print("   8. Изменить Telegram-настройки")
        print("   9. Проверить Email (тест)"); print("  10. Проверить Telegram (тест)")
        print("  11. Ввести API-ключ VirusTotal"); print("   0. Назад в главное меню")
        print("=" * 70)
        try: choice = input("\n   Ваш выбор (0-11): ").strip()
        except (EOFError, KeyboardInterrupt): return
        if choice == "0": return
        elif choice == "3":
            cfg["email_enabled"] = not cfg.get("email_enabled", False)
            save_user_config(cfg); USER_CONFIG = cfg
        elif choice == "4":
            cfg["telegram_enabled"] = not cfg.get("telegram_enabled", False)
            save_user_config(cfg); USER_CONFIG = cfg
        elif choice == "5":
            print(); print("   Введите новый email отправителя (Enter — оставить):")
            v = input("   > ").strip()
            if v: cfg["email_from"] = v
            print("   Введите новый email получателя:")
            v = input("   > ").strip()
            if v: cfg["email_to"] = v
            save_user_config(cfg); USER_CONFIG = cfg
            print("[+] Email-адреса обновлены.")
        elif choice == "6":
            cfg = choose_email_provider_interactive(cfg)
            save_user_config(cfg); USER_CONFIG = cfg
            print("[+] Сервис изменён.")
        elif choice == "7":
            if not cfg.get("email_from") or not cfg.get("email_to"):
                print("\n   [!] Сначала укажите email отправителя и получателя (пункт 5).")
                input("   Нажмите Enter..."); continue
            pwd = input_app_password_with_check(cfg)
            if pwd:
                cfg["email_app_pass"] = pwd; cfg["email_enabled"] = True
                save_user_config(cfg); USER_CONFIG = cfg
                print("[+] Пароль приложения сохранён, email включён.")
            input("   Нажмите Enter...")
        elif choice == "8":
            print(); print("   Введите новый Bot Token (Enter — оставить):")
            v = input("   > ").strip()
            if v: cfg["telegram_bot_token"] = v
            print("   Введите новый Chat ID:")
            v = input("   > ").strip()
            if v: cfg["telegram_chat_id"] = v
            save_user_config(cfg); USER_CONFIG = cfg
            print("[+] Telegram-настройки обновлены.")
        elif choice == "9": test_email()
        elif choice == "10": test_telegram()
        elif choice == "11":
            print()
            cur = cfg.get("vt_api_key", "")
            print(f"   Текущий ключ: {(cur[:12] + '...') if cur else '(не задан)'}")
            print("   Получить новый: https://www.virustotal.com/gui/my-apikey")
            print("   Введите новый API-ключ (Enter — оставить):")
            v = input("   > ").strip()
            if v:
                cfg["vt_api_key"] = v
                save_user_config(cfg); USER_CONFIG = cfg
                print("[+] Ключ VirusTotal сохранён.")
            input("   Нажмите Enter...")
        else: print("[!] Неверный выбор.")


def test_email():
    print(); print("=" * 70); print("   ТЕСТ EMAIL"); print("=" * 70); print()
    send_email_alert(ip="TEST-IP", risk_level="ТЕСТ", total_detections=0,
                     source="Проверка настроек email")
    input("   Нажмите Enter...")


def test_telegram():
    print(); print("=" * 70); print("   ТЕСТ TELEGRAM"); print("=" * 70); print()
    send_telegram_alert(ip="TEST-IP", risk_level="ТЕСТ", total_detections=0,
                        source="Проверка настроек Telegram")
    input("   Нажмите Enter...")

# ============================================================
# СПРАВОЧНИК
# ============================================================
def show_help():
    print(); print("=" * 70); print("   СПРАВОЧНИК"); print("=" * 70)
    print("""
  [1] Пакетное сканирование — реальный: Suricata 15 сек + VT API.
      Имитация: читает data/ip_list_generated.json или ip_list.json.
      Сохраняет отчёт, графики IP, доменов и URL.
      Проверяет IP, домены и URL через VirusTotal.

  [2] История — IP, домены и URL отдельно.

  [3] Ручная проверка — вводите IP, домен или URL.

  [4] Фоновый мониторинг — отдельное свёрнутое окно.

  [5] Справочник — этот текст.

  [6] Уведомления об угрозах.

  [7] Графики по истории — IP, домены и URL отдельно.

  [8] Настройки уведомлений.

  [9] Режим VirusTotal — реальный API или ИМИТАЦИЯ.

  [10] Сгенерировать новые данные для имитации (рандомные IP/домены/URL).
""")
    print("=" * 70)
    try: input("   Нажмите Enter...")
    except (EOFError, KeyboardInterrupt): pass

# ============================================================
# ГЕНЕРАТОР ДАННЫХ ДЛЯ ИМИТАЦИИ
# ============================================================
def generate_fake_menu():
    print(); print("=" * 70); print("   ГЕНЕРАТОР ДАННЫХ ДЛЯ ИМИТАЦИИ"); print("=" * 70)
    print("   Создаёт СЛУЧАЙНЫЙ файл data/ip_list_generated.json")
    print("   с IP, доменами, URL и вердиктами VirusTotal.")
    print("=" * 70); print()
    print("   Сколько IP-адресов сгенерировать? (по умолчанию 8)")
    v = input("   > ").strip()
    try: num_ips = int(v) if v else 8
    except ValueError: num_ips = 8
    if num_ips < 1 or num_ips > 100: num_ips = 8

    print("   Сколько доменов сгенерировать? (по умолчанию 10)")
    v = input("   > ").strip()
    try: num_domains = int(v) if v else 10
    except ValueError: num_domains = 10
    if num_domains < 1 or num_domains > 100: num_domains = 10

    print("   Сколько URL сгенерировать? (по умолчанию 8)")
    v = input("   > ").strip()
    try: num_urls = int(v) if v else 8
    except ValueError: num_urls = 8
    if num_urls < 1 or num_urls > 100: num_urls = 8

    print("   Доля опасных (0.0-1.0, по умолчанию 0.3 = 30%)")
    v = input("   > ").strip()
    try: bad_ratio = float(v) if v else 0.3
    except ValueError: bad_ratio = 0.3
    if bad_ratio < 0.0 or bad_ratio > 1.0: bad_ratio = 0.3

    print(); print(f"   [*] Генерирую: {num_ips} IP, {num_domains} доменов, "
                   f"{num_urls} URL, опасных ~{int(bad_ratio * 100)}%...")
    data = regenerate_fake_data_file(num_ips, num_domains, num_urls, bad_ratio)
    print(); print("=" * 70); print("   ЧТО СГЕНЕРИРОВАНО:"); print("=" * 70)
    print(f"   DNS-событий:     {len(data['dns_events'])}")
    print(f"   URL-событий:     {len(data.get('url_events', []))}")
    print(f"   Записей VT:      {len(data['vt_responses'])}")

    bad_ips = [ip for ip, info in data["vt_responses"].items()
               if info.get("malicious") and "." in ip and ip.replace(".", "").isdigit()]
    bad_domains = [d for d, info in data["vt_responses"].items()
                   if info.get("malicious") and not d.replace(".", "").isdigit()
                   and not d.startswith("http")]
    bad_urls = [u for u, info in data["vt_responses"].items()
                if info.get("malicious") and u.startswith("http")]

    print(f"   Опасных IP:      {len(bad_ips)}")
    print(f"   Опасных доменов: {len(bad_domains)}")
    print(f"   Опасных URL:     {len(bad_urls)}")
    print()
    if bad_ips:
        print("   Примеры опасных IP:")
        for ip in bad_ips[:5]: print(f"     - {ip} ({data['vt_responses'][ip]['risk_level']})")
    if bad_domains:
        print("   Примеры опасных доменов:")
        for d in bad_domains[:5]: print(f"     - {d} ({data['vt_responses'][d]['risk_level']})")
    if bad_urls:
        print("   Примеры опасных URL:")
        for u in bad_urls[:3]: print(f"     - {u} ({data['vt_responses'][u]['risk_level']})")
    print("=" * 70); print()
    print("   [i] Теперь переключитесь в режим ИМИТАЦИИ (пункт 9 → 2)")
    print("   [i] И запускайте сканирование (пункт 1) — данные подхватятся.")
    print()
    input("   Нажмите Enter...")

# ============================================================
# ПЕРЕКЛЮЧЕНИЕ РЕЖИМА VIRUSTOTAL
# ============================================================
def switch_vt_mode():
    global VT_MODE, USER_CONFIG
    while True:
        print(); print("=" * 70); print("   РЕЖИМ VIRUSTOTAL"); print("=" * 70)
        print(f"   Текущий режим: {'ИМИТАЦИЯ' if VT_MODE == 'fake' else 'РЕАЛЬНЫЙ API'}")
        cur_key = get_vt_api_key()
        print(f"   API-ключ:      {'задан' if cur_key else '(не задан)'}")
        if cur_key: print(f"                  {cur_key[:16]}...{cur_key[-4:]}")
        print(); print("   1. Реальный API (нужен интернет и ключ)")
        print("   2. Имитация (данные из ip_list_generated.json, без интернета)")
        print("   3. ← Ввести/сменить API-ключ VirusTotal")
        print("   0. Назад"); print("=" * 70)
        try: choice = input("\n   Ваш выбор (0-3): ").strip()
        except (EOFError, KeyboardInterrupt): return
        if choice == "1":
            VT_MODE = "real"; USER_CONFIG["vt_mode"] = "real"
            save_user_config(USER_CONFIG)
            if not get_vt_api_key():
                print("\n[!] Внимание: API-ключ VirusTotal не задан.")
                print("    Выберите пункт 3, чтобы ввести его.")
            print("\n[+] Включён РЕАЛЬНЫЙ режим VirusTotal.")
            input("   Нажмите Enter...")
        elif choice == "2":
            VT_MODE = "fake"; USER_CONFIG["vt_mode"] = "fake"
            save_user_config(USER_CONFIG)
            print("\n[+] Включён режим ИМИТАЦИИ.")
            print("    Реальные запросы к VirusTotal отправляться НЕ будут.")
            print(f"    Данные берутся из файла: {FAKE_GENERATED_FILE}")
            input("   Нажмите Enter...")
        elif choice == "3":
            print()
            cur = get_vt_api_key()
            print(f"   Текущий ключ: {(cur[:16] + '...' + cur[-4:]) if cur else '(не задан)'}")
            print("   Получить новый: https://www.virustotal.com/gui/my-apikey")
            print("   Введите новый API-ключ (Enter — оставить):")
            v = input("   > ").strip()
            if v:
                USER_CONFIG["vt_api_key"] = v
                save_user_config(USER_CONFIG)
                print("[+] Ключ VirusTotal сохранён.")
                print(f"    Теперь задан: {v[:16]}...{v[-4:]}")
            else: print("[i] Ключ не изменён.")
            input("   Нажмите Enter...")
        elif choice == "0": return
        else: print("[!] Неверный выбор.")

# ============================================================
# ГЛАВНОЕ МЕНЮ
# ============================================================
def main_menu():
    global USER_CONFIG, VT_MODE
    init_db()
    USER_CONFIG = ensure_user_config()
    VT_MODE = USER_CONFIG.get("vt_mode", "real")
    key_status = "задан" if get_vt_api_key() else "НЕ ЗАДАН"
    print(f"[i] Режим VirusTotal: {'ИМИТАЦИЯ' if VT_MODE == 'fake' else 'РЕАЛЬНЫЙ API'}")
    print(f"[i] API-ключ VirusTotal: {key_status}")

    while True:
        print(); print("=" * 70); print("   ГЛАВНОЕ МЕНЮ"); print("=" * 70)
        print("   1. Запустить новое сканирование (пакетный режим)")
        print("   2. Посмотреть историю сканирований")
        print("   3. Проверить IP, домен или URL вручную")
        print("   4. Фоновый мониторинг в реальном времени")
        print("   5. Справочник / Инфо")
        print("   6. Уведомления об угрозах (pending)")
        print("   7. Построить графики по истории")
        print("   8. Настройки уведомлений")
        print("   9. Режим VirusTotal (реальный/имитация)")
        print("  10. Сгенерировать новые данные для имитации")
        print("  11. Выход")
        print("=" * 70)
        try: choice = input("\n   Выберите действие (1-11): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Выход..."); break

        if choice == "1":   run_scan()
        elif choice == "2": view_history()
        elif choice == "3": manual_check()
        elif choice == "4": realtime_monitor()
        elif choice == "5": show_help()
        elif choice == "6": check_pending_alerts()
        elif choice == "7": build_history_charts()
        elif choice == "8": edit_notification_settings()
        elif choice == "9": switch_vt_mode()
        elif choice == "10": generate_fake_menu()
        elif choice == "11":
            print("\n[*] Выход..."); break
        else: print("\n[!] Неверный выбор.")

# ============================================================
# ОБРАБОТЧИК ЗАКРЫТИЯ
# ============================================================
def console_ctrl_handler(ctrl_type):
    if ctrl_type in (0, 1, 2, 5, 6):
        emergency_stop_suricata()
    return False

try:
    if sys.platform == "win32":
        handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
        handler = handler_type(console_ctrl_handler)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True)
except Exception as e:
    print(f"[!] Не удалось зарегистрировать обработчик: {e}")

# ============================================================
# ТОЧКА ВХОДА
# ============================================================
if __name__ == "__main__":
    if "--monitor-worker" in sys.argv:
        if "--vt-mode" in sys.argv:
            try:
                idx = sys.argv.index("--vt-mode")
                mode_arg = sys.argv[idx + 1]
                if mode_arg in ("real", "fake"):
                    VT_MODE = mode_arg
            except Exception:
                pass
        realtime_monitor_worker()
    else:
        main_menu()