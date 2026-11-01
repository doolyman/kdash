"""Verify served encrypted dashboard files; no credentials or data are uploaded."""
import hashlib
from pathlib import Path
import time
import urllib.error
import urllib.request
import uuid

BASE = 'https://doolyman.github.io/kdash/'
FILES = ('index.html', 'enc.js', 'data/manifest.json', 'data/watch_trade.bin', 'data/dates.bin')


def fetch(url):
    request = urllib.request.Request(url, headers={'Cache-Control': 'no-cache', 'User-Agent': 'kdash-publish-check/1.0'})
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read()


def verify(root, attempts=12, delay=10, opener=fetch, sleep=time.sleep):
    expected = {name: hashlib.sha256((root / name).read_bytes()).digest() for name in FILES}
    for attempt in range(1, attempts + 1):
        pending = []
        nonce = uuid.uuid4().hex
        for name in FILES:
            try:
                content = opener(BASE + name + '?publish_check=' + nonce)
                matches = hashlib.sha256(content).digest() == expected[name]
            except (urllib.error.URLError, TimeoutError, OSError):
                matches = False
            if not matches:
                pending.append(name)
        if not pending:
            print('Published dashboard verified: all 5 file hashes match.')
            return True
        print(f'Published content pending ({attempt}/{attempts}): ' + ', '.join(pending))
        if attempt < attempts:
            sleep(delay)
    print('Publication is NOT verified. The site still differs from this commit or is unreachable.')
    return False


if __name__ == '__main__':
    raise SystemExit(0 if verify(Path.cwd()) else 1)
