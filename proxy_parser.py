from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import unquote
import gzip
import zlib
import re
import time
import sys
import os

SUBSCRIPTION_URL = "https://ssconnect.app/?url_ha=https://flaregate.dedyn.io/api/v1/sub/vzrGejo9nND3VsEpqeeW6g"
OUTPUT = Path("frgt.txt")
CACHE_DIR = Path(".cache")
CACHE_FILE = CACHE_DIR / "frgt.txt"
RAW_DIR = Path(".raw")
CACHE_TTL = int(os.getenv("SUBSCRIPTION_CACHE_TTL", "1800"))

# Original application identity. Kept unchanged from the supplied parser.
USER_AGENT = "Happ/4.4.1/Android/17891107313301967618"
DEVICE_OS = "Android"
DEVICE_VER_OS = "16"
DEVICE_MODEL = "24117RN76O"
HWID = "6b77631a1de1c0e8"
DEVICE_LOCALE = "ru"

# Optional browser-like HTTP profile.
# Default is OFF so the supplied, already-tested Happ request remains unchanged.
# Set BROWSER_MODE=1 when the endpoint specifically requires browser-like headers.
BROWSER_MODE = os.getenv("BROWSER_MODE", "0").strip().lower() in {
    "1", "true", "yes", "on"
}
BROWSER_USER_AGENT = os.getenv(
    "BROWSER_USER_AGENT",
    "Mozilla/5.0 (Linux; Android 16; 24117RN76O) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Mobile Safari/537.36",
)


def build_headers(browser=False):
    headers = {
        "User-Agent": USER_AGENT,
        "X-Device-Os": DEVICE_OS,
        "X-Device-Locale": DEVICE_LOCALE,
        "X-Device-Model": DEVICE_MODEL,
        "X-Ver-Os": DEVICE_VER_OS,
        "X-Hwid": HWID,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }

    if browser:
        headers.update({
            "User-Agent": BROWSER_USER_AGENT,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        })

    return headers


def decode_body(raw, encoding):
    encoding = (encoding or "").lower()
    if encoding == "gzip":
        return gzip.decompress(raw)
    if encoding == "deflate":
        try:
            return zlib.decompress(raw)
        except zlib.error:
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    return raw


def http_get(url, browser=None):
    if browser is None:
        browser = BROWSER_MODE

    req = Request(url, headers=build_headers(browser=browser), method="GET")
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
RE_HAPP_DEEPLINK = re.compile(r"happ://add/(https?://[^\s\"'<>]+)", re.IGNORECASE)
RE_SUB_URL = re.compile(
    r"https?://[^\s\"'<>]+/api/v1/sub/[A-Za-z0-9_\-]+",
    re.IGNORECASE,
)
RE_GENERIC_HTTP = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def looks_like_html(body, headers):
    ctype = (headers.get("Content-Type") or "").lower()
    if "html" in ctype:
        return True
    head = body[:200].lstrip().lower()
    return head.startswith(b"<!doctype") or head.startswith(b"<html") or b"<html" in head


def is_proxy_config(body):
    sample = body[:5000]
    markers = (
        b"vless://", b"vmess://", b"trojan://", b"ss://",
        b"socks://", b"hy2://", b"hysteria2://", b"hysteria://"
    )
    return any(m in sample for m in markers)


def extract_real_url(html, original_url):
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


def valid_cache():
    return CACHE_FILE.exists() and (time.time() - CACHE_FILE.stat().st_mtime) < CACHE_TTL


def ensure_output():
    if not OUTPUT.exists():
        OUTPUT.write_bytes(b"")


def save_raw(name, url, status, headers, body):
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RAW_DIR / (name + "_body.bin")).write_bytes(body)
    with (RAW_DIR / (name + "_headers.txt")).open("w", encoding="utf-8") as f:
        f.write("URL: " + url + "\n")
        f.write("Status: " + str(status) + "\n")
        for k, v in headers.items():
            f.write(k + ": " + v + "\n")


def fetch_subscription():
    final_url, status, headers, body = http_get(SUBSCRIPTION_URL)
    save_raw("phase1", final_url, status, headers, body)

    if is_proxy_config(body):
        return body

    if not looks_like_html(body, headers):
        return body

    real_url = extract_real_url(body, SUBSCRIPTION_URL)
    if not real_url:
        return body

    final_url2, status2, headers2, body2 = http_get(real_url)
    save_raw("phase2", final_url2, status2, headers2, body2)
    return body2


def main():
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
