from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
import gzip
import zlib
import re
import time
import sys
import os
import ssl
import random

# ---------------------------------------------------------------- config

SUBSCRIPTION_URL = (
    "https://ssconnect.app/?url_ha="
    "https://flaregate.dedyn.io/api/v1/sub/7wH9ySRsmQizQNdQjkcing"
)
OUTPUT = Path("frgt.txt")
CACHE_DIR = Path(".cache")
CACHE_FILE = CACHE_DIR / "frgt.txt"
RAW_DIR = Path(".raw")
CACHE_TTL = int(os.getenv("SUBSCRIPTION_CACHE_TTL", "1800"))
NO_CACHE = os.getenv("SUBSCRIPTION_NO_CACHE", "").lower() in ("1", "true", "yes")

# ---------------------------------------------------------------- brotli

try:
    import brotli  # type: ignore
    _HAS_BROTLI = True
except Exception:
    _HAS_BROTLI = False

# ---------------------------------------------------------------- headers

# Реалистичный набор заголовков Chrome 131 на Android.
_CHROME_UA = (
    "Mozilla/5.0 (Linux; Android 14; 24117RN76O) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.6778.135 Mobile Safari/537.36"
)


def browser_headers(referer: str | None = None, accept_html: bool = True) -> dict:
    """Полноценная имитация браузера Chrome на Android."""
    if accept_html:
        accept = (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        )
    else:
        accept = "*/*"

    h = {
        "User-Agent": _CHROME_UA,
        "Accept": accept,
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br, zstd" if _HAS_BROTLI else "gzip, deflate",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-CH-UA": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
        "Sec-CH-UA-Mobile": "?1",
        "Sec-CH-UA-Platform": '"Android"',
        "Sec-CH-UA-Platform-Version": '"14.0.0"',
        "Sec-CH-UA-Model": '"24117RN76O"',
        "Sec-CH-UA-Full-Version-List": (
            '"Chromium";v="131.0.6778.135", "Not_A Brand";v="24.0.0.0", '
            '"Google Chrome";v="131.0.6778.135"'
        ),
        "Sec-Fetch-Site": "none" if not referer else "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "DNT": "1",
        "Priority": "u=0, i",
    }
    if referer:
        h["Referer"] = referer
    return h


# Фирменные заголовки приложения Happ (Proxy utility).
HAPP_UA = "Happ/4.4.1/Android/17891107313301967618"


def happ_headers(referer: str | None = None) -> dict:
    h = {
        "User-Agent": HAPP_UA,
        "X-Device-Os": "Android",
        "X-Device-Locale": "ru",
        "X-Device-Model": "24117RN76O",
        "X-Ver-Os": "16",
        "X-Hwid": "6b77631a1de1c0e8",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "X-App-Version": "4.4.1",
        "X-App-Name": "Happ",
        "X-Requested-With": "Happ",
    }
    if referer:
        h["Referer"] = referer
    return h


# ---------------------------------------------------------------- decoding

def decode_body(raw: bytes, encoding: str) -> bytes:
    encoding = (encoding or "").lower().strip()
    if not encoding:
        return raw
    if encoding == "gzip":
        return gzip.decompress(raw)
    if encoding == "deflate":
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    if encoding == "br" and _HAS_BROTLI:
        return brotli.decompress(raw)
    if encoding == "zstd":
        try:
            import zstandard  # type: ignore
            return zstandard.ZstdDecompressor().decompress(raw)
        except Exception:
            return raw
    return raw


# ---------------------------------------------------------------- http

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def http_get(url: str, headers: dict, label: str):
    req = Request(url, headers=headers, method="GET")
    opener = build_opener(HTTPRedirectHandler())
    try:
        with opener.open(req, timeout=30, context=_CTX) as resp:
            final_url = resp.geturl()
            status = resp.status
            hdrs = dict(resp.headers)
            raw = resp.read()
    except HTTPError as e:
        final_url = e.geturl()
        status = e.code
        hdrs = dict(e.headers or {})
        raw = e.read()
    body = decode_body(raw, hdrs.get("Content-Encoding", ""))
    return final_url, status, hdrs, body


# ---------------------------------------------------------------- parsing

RE_URL_HA = re.compile(r"[?&]url_ha=([^&\s\"'<>]+)", re.IGNORECASE)
RE_HAPP_DEEPLINK = re.compile(r"happ://add/(https?://[^\s\"'<>)]+)", re.IGNORECASE)
RE_SUB_URL = re.compile(r"https?://[^\s\"'<>]+/api/v1/sub/[A-Za-z0-9_\-]+", re.IGNORECASE)
RE_GENERIC_HTTP = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def looks_like_html(body: bytes, headers: dict) -> bool:
    ctype = (headers.get("Content-Type") or "").lower()
    if "html" in ctype:
        return True
    head = body[:300].lstrip().lower()
    return (
        head.startswith(b"<!doctype")
        or head.startswith(b"<html")
        or b"<html" in head
        or b"<body" in head
    )


def is_proxy_config(body: bytes) -> bool:
    sample = body[:8000]
    markers = (
        b"vless://", b"vmess://", b"trojan://", b"ss://",
        b"socks://", b"hy2://", b"hysteria2://", b"hysteria://",
        b"tuic://", b"wireguard://", b"ssh://",
    )
    return any(m in sample for m in markers)


def extract_real_url(html: bytes, original_url: str) -> str | None:
    text = html.decode("utf-8", errors="replace")

    # 1. happ://add/<url>
    m = RE_HAPP_DEEPLINK.search(text)
    if m:
        return unquote(m.group(1))

    # 2. url_ha=... в исходном URL
    m = RE_URL_HA.search(original_url)
    if m:
        return unquote(m.group(1))

    # 3. Прямая ссылка /api/v1/sub/...
    m = RE_SUB_URL.search(text)
    if m:
        return m.group(0)

    # 4. Любая http(s)-ссылка, где есть "sub" и это не сам ssconnect.app
    for m in RE_GENERIC_HTTP.finditer(text):
        candidate = m.group(0).rstrip(".,;\"')")
        low = candidate.lower()
        host = urlparse(candidate).netloc.lower()
        if "sub" in low and "ssconnect.app" not in host:
            return candidate

    return None


# ---------------------------------------------------------------- cache

def valid_cache() -> bool:
    if NO_CACHE:
        return False
    return CACHE_FILE.exists() and (time.time() - CACHE_FILE.stat().st_mtime) < CACHE_TTL


def ensure_output():
    if not OUTPUT.exists():
        OUTPUT.write_bytes(b"")


def save_raw(name: str, url: str, status: int, headers: dict, body: bytes):
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RAW_DIR / (name + "_body.bin")).write_bytes(body)
    with (RAW_DIR / (name + "_headers.txt")).open("w", encoding="utf-8") as f:
        f.write("URL: " + url + "\n")
        f.write("Status: " + str(status) + "\n")
        for k, v in headers.items():
            f.write(k + ": " + v + "\n")


# ---------------------------------------------------------------- pipeline

def fetch_subscription() -> bytes:
    """
    Фаза 1 — ssconnect.app как браузер Chrome.
    Фаза 2 — реальная подписка как приложение Happ.
    """
    # --- Фаза 1: браузер ---
    h1 = browser_headers(accept_html=True)
    final_url, status, headers, body = http_get(SUBSCRIPTION_URL, h1, "browser")
    save_raw("phase1_browser", final_url, status, headers, body)

    # Если сервер сразу отдал прокси-конфиг — отдаём как есть
    if is_proxy_config(body):
        return body

    # Если это не HTML и не прокси-конфиг — вернём как есть
    if not looks_like_html(body, headers):
        return body

    # --- Извлекаем реальную ссылку ---
    real_url = extract_real_url(body, SUBSCRIPTION_URL)
    if not real_url:
        return body

    # --- Фаза 2: приложение Happ ---
    h2 = happ_headers(referer="https://ssconnect.app/")
    final_url2, status2, headers2, body2 = http_get(real_url, h2, "happ")
    save_raw("phase2_happ", final_url2, status2, headers2, body2)

    # Если Happ-запрос не дал прокси-конфиг — повторяем как браузер
    if not is_proxy_config(body2):
        h3 = browser_headers(referer="https://ssconnect.app/", accept_html=False)
        final_url3, status3, headers3, body3 = http_get(real_url, h3, "browser_fallback")
        save_raw("phase2_browser_fallback", final_url3, status3, headers3, body3)
        if is_proxy_config(body3):
            return body3

    return body2


def main() -> int:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ensure_output()

    try:
        body = fetch_subscription()
        if not body:
            raise RuntimeError("empty body")

        OUTPUT.write_bytes(body)
        CACHE_FILE.write_bytes(body)
        return 0

    except (HTTPError, URLError, RuntimeError, OSError) as e:
        print("error:", e, file=sys.stderr)
        if valid_cache() or CACHE_FILE.exists():
            OUTPUT.write_bytes(CACHE_FILE.read_bytes())
            return 0
        OUTPUT.write_bytes(b"")
        return 1


if __name__ == "__main__":
    sys.exit(main())
