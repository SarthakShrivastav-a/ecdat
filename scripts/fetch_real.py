"""Download real open-source repositories (zip archives, no VCS needed) for the REAL_RUNS demo scans."""
from __future__ import annotations

import io
import sys
import urllib.request
import zipfile
from pathlib import Path

REPOS = {
    "pyjwt": "https://github.com/jpadilla/pyjwt/archive/refs/heads/master.zip",
    "python-jose": "https://github.com/python-jose/python-jose/archive/refs/heads/master.zip",
    "node-jsonwebtoken": "https://github.com/auth0/node-jsonwebtoken/archive/refs/heads/master.zip",
    "paramiko": "https://github.com/paramiko/paramiko/archive/refs/heads/main.zip",
}


def fetch(dest: Path, names: list[str] | None = None) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    out = []
    for name, url in REPOS.items():
        if names and name not in names:
            continue
        target = dest / name
        if target.exists() and any(target.iterdir()):
            out.append(target)
            continue
        print(f"fetching {name} ...", flush=True)
        data = None
        for candidate in (url, url.replace("/master.zip", "/main.zip"), url.replace("/main.zip", "/master.zip")):
            try:
                with urllib.request.urlopen(candidate, timeout=120) as r:
                    data = r.read()
                break
            except Exception as exc:
                print(f"  {candidate}: {exc}")
        if data is None:
            continue
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            root = z.namelist()[0].split("/")[0]
            z.extractall(dest / "_tmp")
        (dest / "_tmp" / root).rename(target)
        out.append(target)
        print(f"  {name}: {sum(1 for _ in target.rglob('*') if _.is_file())} files")
    return out


if __name__ == "__main__":
    fetch(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/real-src"), sys.argv[2:] or None)
