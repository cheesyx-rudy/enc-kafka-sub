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

SUBSCRIPTION_URL = "https://ssconnect.app/?url_ha=https://flaregate.dedyn.io/api/v1/sub/RBg-rdgFRmfmlWA1m3ud3g"
OUTPUT = Path("frgt.txt")
CACHE_DIR = Path(".cache")
CACHE_FILE = CACHE_DIR / "frgt.txt"
RAW_DIR = Path(".raw")
CACHE_TTL = int(os.getenv("SUBSCRIPTION_CACHE_TTL", "1800"))

# ---------- Happ (Proxy utility) profile ----------
HAPP_USER_AGENT = "Happ/4.4.1/Android/17891107313301967618"
HAPP_DEVICE_OS = "Android"
HAPP_DEVICE_VER_OS = "16"
HAPP_DEVICE_MODEL = "24117RN76O"
HAPP_HWID = "6b77631a1de1c0e8"
HAPP_DEVICE_LOCALE = "ru"

# ---------- Browser (Chrome on Android) profile ----------
BROWSER_UA = (
    "Mozilla/5.0 (Linux; Android 16; 24117RN76O Build/BP2A.250605.031.A2; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.7390.122 "
    "Mobile Safari/537.36"
)
BROWSER_ACCEPT_LANGUAGE = "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"
BROWSER_SEC_CH_UA = '"Chromium";v="141", "Not?A_Brand";v="24", "Google Chrome";v="141"'
BROWSER_SEC_CH_UA_MOBILE = "?1"
BROWSER_SEC_CH_UA_PLATFORM = '"Android"'
BROWSER_SEC_CH_UA_FULL_VERSION = '"141.0.7390.122"'
BROWSER_SEC_CH_UA_FULL_VERSION_LIST = (
    '"Chromium";v="141.0.7390.122", "Not?A_Brand";v="24.0.0.0", '
    '"Google Chrome";v="141.0.7390.122"'
)


def build_browser_headers(url: str) -> dict:
    """Полноценная имитация браузера Chrome на Android."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return {
        "Host": parsed.netloc,
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
        "sec-ch-ua": BROWSER_SEC_CH_UA,
        "sec-ch-ua-mobile": BROWSER_SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": BROWSER_SEC_CH_UA_PLATFORM,
        "sec-ch-ua-full-version": BROWSER_SEC_CH_UA_FULL_VERSION,
        "sec-ch-ua-full-version-list": BROWSER_SEC_CH_UA_FULL_VERSION_LIST,
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": BROWSER_UA,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": BROWSER_ACCEPT_LANGUAGE,
        "Priority": "u=0, i",
        "Referer": origin + "/",
    }


def build_happ_headers() -> dict:
    """Имитация приложения Happ — Proxy utility."""
    return {
        "User-Agent": HAPP_USER_AGENT,
        "X-Device-Os": HAPP_DEVICE_OS,
        "X-Device-Locale": HAPP_DEVICE_LOCALE,
        "X-Device-Model": HAPP_DEVICE_MODEL,
        "X-Ver-Os": HAPP_DEVICE_VER_OS,
        "X-Hwid": HAPP_HWID,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }


def build_headers(kind: str, url: str) -> dict:
    if kind == "browser":
        return build_browser_headers(url)
    if kind == "happ":
        return build_happ_headers()
    raise ValueError(f"unknown header kind: {kind}")


def decode_body(raw: bytes, encoding: str) -> bytes:
    encoding = (encoding or "").lower()
    if encoding == "gzip":
        return gzip.decompress(raw)
    if encoding == "deflate":
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    if encoding == "br":
        try:
            import brotli  # type: ignore
            return brotli.decompress(raw)
        except Exception:
            # fallback: brotli не установлен — вернём как есть
            return raw
    return raw


def http_get(url: str, kind: str):
    req = Request(url, headers=build_headers(kind, url), method="GET")
    opener = build_opener(HTTPRedirectHandler())
    try:
        with opener.open(req, timeout=30) as resp:
            final_url = resp.geturl()
            status = resp.status
            headers = dict(resp.headers)
            raw = resp.read()
    except HTTPError as e:
        final_url = e.geturl()
        status = e.code
        headers = dict(e.headers or {})
        raw = e.read()
    body = decode_body(raw, headers.get("Content-Encoding", ""))
    return final_url, status, headers, body


RE_URL_HA = re.compile(r"[?&]url_ha=([^&\s\"'<>]+)", re.IGNORECASE)
RE_HAPP_DEEPLINK = re.compile(r"happ://add/(https?://[^\s\"'<>)]+)", re.IGNORECASE)
RE_SUB_URL = re.compile(r"https?://[^\s\"'<>]+/api/v1/sub/[A-Za-z0-9_\-]+", re.IGNORECASE)
RE_GENERIC_HTTP = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def looks_like_html(body: bytes, headers: dict) -> bool:
    ctype = (headers.get("Content-Type") or "").lower()
    if "html" in ctype:
        return True
    head = body[:200].lstrip().lower()
    return head.startswith(b"<!doctype") or head.startswith(b"<html") or b"<html" in head


def is_proxy_config(body: bytes) -> bool:
    sample = body[:5000]
    markers = (b"vless://", b"vmess://", b"trojan://", b"ss://",
               b"socks://", b"hy2://", b"hysteria2://", b"hysteria://")
    return any(m in sample for m in markers)


def extract_real_url(html: bytes, original_url: str):
    text = html.decode("utf-8", errors="replace")

    m = RE_HAPP_DEEPLINK.search(text)
    if m:
        return unquote(m.group(1))

    m = RE_URL_HA.search(original_url)
    if m:
        return unquote(m.group(1))

    m = RE_SUB_URL.search(text)
    if m:
        return m.group(0)

    for m in RE_GENERIC_HTTP.finditer(text):
        candidate = m.group(0)
        if "sub" in candidate.lower() and "ssconnect.app" not in candidate:
            return candidate

    return None


def valid_cache() -> bool:
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


def fetch_subscription() -> bytes:
    # Этап 1: имитация браузера
    final_url, status, headers, body = http_get(SUBSCRIPTION_URL, kind="browser")
    save_raw("phase1", final_url, status, headers, body)

    if is_proxy_config(body):
        return body

    if not looks_like_html(body, headers):
        return body

    real_url = extract_real_url(body, SUBSCRIPTION_URL)
    if not real_url:
        return body

    # Этап 2: имитация приложения Happ
    final_url2, status2, headers2, body2 = http_get(real_url, kind="happ")
    save_raw("phase2", final_url2, status2, headers2, body2)
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
        print("error:", e)
        if valid_cache():
            OUTPUT.write_bytes(CACHE_FILE.read_bytes())
            return 0
        if CACHE_FILE.exists():
            OUTPUT.write_bytes(CACHE_FILE.read_bytes())
            return 0
        OUTPUT.write_bytes(b"")
        return 1


if __name__ == "__main__":
    sys.exit(main())
