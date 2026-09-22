from pathlib import Path
from urllib.request import Request, urlopen
import os
import time

SOURCES = Path("sources.txt")
OUTPUT = Path("frgt.txt")
CACHE_DIR = Path(".cache")
CACHE_FILE = CACHE_DIR / "frgt.txt"
CACHE_TTL = int(os.getenv("SUBSCRIPTION_CACHE_TTL", "1800"))
USER_AGENT = os.getenv("SUBSCRIPTION_USER_AGENT", "Happ/1.0")


def read_sources():
    if not SOURCES.exists():
        return []
    return [
        line.strip()
        for line in SOURCES.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def fetch(url):
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=30) as response:
        return response.read()


def valid_cache():
    return CACHE_FILE.exists() and time.time() - CACHE_FILE.stat().st_mtime < CACHE_TTL


def main():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    sources = read_sources()

    chunks = []
    for url in sources:
        try:
            data = fetch(url)
            if data:
                chunks.append(data)
        except Exception as e:
            print(f"Source failed: {url}: {e}")

    if chunks:
        # Чистый парсер: ничего не фильтируем и не преобразуем.
        result = b"\n".join(chunks)
        OUTPUT.write_bytes(result)
        CACHE_FILE.write_bytes(result)
        print(f"Generated {OUTPUT} from {len(chunks)} source(s)")
    elif valid_cache():
        OUTPUT.write_bytes(CACHE_FILE.read_bytes())
        print("Sources unavailable; restored cached frgt.txt")
    elif CACHE_FILE.exists():
        OUTPUT.write_bytes(CACHE_FILE.read_bytes())
        print("Sources unavailable; restored existing cached frgt.txt")
    else:
        OUTPUT.write_bytes(b"")
        print("No source data and no cache")


if __name__ == "__main__":
    main()
