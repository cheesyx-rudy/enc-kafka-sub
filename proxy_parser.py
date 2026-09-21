#!/usr/bin/env python3
import argparse, base64, json, os, re, urllib.error, urllib.parse, urllib.request
from pathlib import Path
from datetime import datetime, timezone, timedelta

SOURCES_FILE = Path("proxy_sources.txt")
OUTPUT_FILE = Path("frgt.txt")
MAX_BYTES = 20 * 1024 * 1024

URI_RE = re.compile(r"(?i)\b(?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|anytls|socks5?|http)://[^\s<>\"']+")

def load_pass():
    value = os.environ.get("PASS", "").strip()
    if value:
        return value
    env_path = Path(".env")
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            if key.strip() == "PASS":
                return val.strip().strip('\"').strip("'")
    raise SystemExit("PASS is not set: provide PASS in the environment or in .env")


def fetch(url, password):
    payload = json.dumps({"url": url, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        "https://quic.best/pass",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read(MAX_BYTES + 1)
            status = r.status
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"API returned HTTP {e.code}: {body[:1000]}") from e
    if status < 200 or status >= 300:
        raise RuntimeError(f"API returned HTTP {status}")
    if len(data) > MAX_BYTES:
        raise ValueError("API response is larger than 20 MiB")
    return data.decode("utf-8", errors="replace")

def extract_uris(text, depth=0):
    if depth > 3:
        return []
    found = [x.rstrip(".,;:)]}>\"'") for x in URI_RE.findall(text)]
    compact = re.sub(r"\s+", "", text)
    if depth < 3 and len(compact) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            decoded = base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", errors="replace")
            if decoded != text:
                found.extend(extract_uris(decoded, depth + 1))
        except Exception:
            pass
    if depth < 2:
        try:
            found.extend(extract_uris(json.dumps(json.loads(text), ensure_ascii=False), depth + 1))
        except Exception:
            pass
    return found

def is_mlkem_encryption_proxy(uri):
    raw = uri.split("#", 1)[0]
    try:
        parsed = urllib.parse.urlsplit(raw)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key, values in query.items():
            if key.lower() == "encryption":
                for value in values:
                    value = urllib.parse.unquote(str(value or "")).strip().lower()
                    if value.startswith("mlkem768x25519plus"):
                        return True
        if parsed.scheme.lower() == "vmess":
            payload = urllib.parse.unquote(parsed.netloc + parsed.path).strip()
            decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8", errors="replace")
            obj = json.loads(decoded)
            if isinstance(obj, dict) and str(obj.get("encryption") or "").strip().lower().startswith("mlkem768x25519plus"):
                return True
    except Exception:
        pass
    return False

def rename_uri(uri, number):
    label = f"🇧🇩 Бангладеш | Bangladesh #{number}"
    return uri.split("#", 1)[0] + "#" + urllib.parse.quote(label, safe="")

def load_dead_numbers():
    path = Path("dead.txt")
    if not path.exists():
        return set()
    result = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.isdigit() and int(line) > 0:
            result.add(int(line))
    return result

def write_snapshot(proxies):
    Path("parsed_proxies.txt").write_text("\n".join(proxies) + ("\n" if proxies else ""), encoding="utf-8")

def read_snapshot():
    path = Path("parsed_proxies.txt")
    if not path.exists():
        raise SystemExit("parsed_proxies.txt not found")
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]

def apply_dead_numbers(proxies, dead_numbers):
    if not dead_numbers:
        return proxies, 0
    result, removed = [], 0
    for number, uri in enumerate(proxies, start=1):
        if number in dead_numbers:
            removed += 1
            print(f"[DEAD] removed proxy #{number}")
        else:
            result.append(uri)
    return result, removed

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("fresh", "cleanup"), default="fresh")
    args = parser.parse_args()
    snapshot = Path("parsed_proxies.txt")

    if args.mode == "cleanup":
        dead_numbers = load_dead_numbers()
        if not snapshot.exists():
            raise SystemExit("parsed_proxies.txt not found; run --mode fresh first")
        if not dead_numbers:
            raise SystemExit("dead.txt is empty; add failed Happ proxy numbers first")
        unique = read_snapshot()
        print(f"[MODE] cleanup: using frozen snapshot ({len(unique)} proxy URLs)")
        print(f"[DEAD] loaded {len(dead_numbers)} manually marked proxy numbers")
        unique, removed = apply_dead_numbers(unique, dead_numbers)
        print(f"[DEAD] removed {removed} dead proxies")
    else:
        if not SOURCES_FILE.exists():
            raise SystemExit("proxy_sources.txt not found")
        sources = [x.strip() for x in SOURCES_FILE.read_text(encoding="utf-8").splitlines() if x.strip() and not x.lstrip().startswith("#")]
        if len(sources) != 1:
            raise SystemExit(f"proxy_sources.txt must contain exactly one source URL, found {len(sources)}")
        password = load_pass()
        unique, seen = [], set()
        mlkem_skipped = 0
        for source in sources:
            try:
                items = extract_uris(fetch(source, password))
                added = 0
                source_mlkem = 0
                for uri in items:
                    key = uri.split("#", 1)[0]
                    if key in seen:
                        continue
                    seen.add(key)
                    if is_mlkem_encryption_proxy(uri):
                        mlkem_skipped += 1
                        source_mlkem += 1
                        continue
                    unique.append(uri)
                    added += 1
                print(f"[SOURCE] {source} -> API /pass -> {added} new proxy URLs" + (f" (skipped {source_mlkem} ML-KEM)" if source_mlkem else ""))
            except Exception as e:
                print(f"[SOURCE ERROR] {source}: {e}")
        print(f"[FILTER] skipped {mlkem_skipped} ML-KEM encryption proxies")
        write_snapshot(unique)
        print(f"[SNAPSHOT] saved {len(unique)} proxy URLs to parsed_proxies.txt")

    output = [rename_uri(uri, index) for index, uri in enumerate(unique, start=1)]
    updated = (datetime.now(timezone.utc) + timedelta(hours=3)).strftime("%d.%m.%Y %H:%M")
    header = (
        "#subscription-userinfo: upload=1073741824000; download=0; total=1073741824000; expire=2524608000\n"
        "#profile-title: frgt\n"
        "#profile-update-interval: 1\n"
        f"#announce: rudy & cheesyx // обновлено: {updated} | конфигов: {len(output)}"
    )
    result = header + "\n" + "\n".join(output)
    tmp = OUTPUT_FILE.with_suffix(".tmp")
    tmp.write_text(result + ("\n" if output else ""), encoding="utf-8")
    tmp.replace(OUTPUT_FILE)
    print(f"[TOTAL] {len(output)} unique proxy URLs")
    print(f"[DONE] wrote {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
