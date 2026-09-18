"""CBOM Atlas: scan ~100 public repositories with ECDAT, one signed CBOM each, then aggregate.

    python scripts/atlas.py verify            # resolve repos via the GitHub API -> out/atlas/manifest.json
    python scripts/atlas.py fetch  [-j 6]     # download zip archives -> out/atlas/src/<slug>
    python scripts/atlas.py scan   [-j 3]     # one `ecdat scan` per repo -> out/atlas/scans/<slug>
    python scripts/atlas.py run    [-j 2]     # fetch -> scan -> delete source, per repo (low-disk mode)
    python scripts/atlas.py aggregate         # -> out/atlas/atlas.json + atlas.md

Every step is resumable: finished repos are skipped. Nothing is pushed anywhere.
"""
from __future__ import annotations

import argparse
import shutil
import io
import json
import subprocess
import sys
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from atlas_repos import CATEGORIES, REPOS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "atlas"
MAX_SIZE_KB = 560_000  # GitHub size includes git history; the branch zip is much smaller
SCAN_TIMEOUT_S = 900
DATA_CLASS_ALIASES = {"default": "generic"}


def slug(full: str) -> str:
    return full.replace("/", "__")


def verify() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for full, category, data_class in REPOS:
        proc = subprocess.run(["gh", "api", f"repos/{full}"], capture_output=True, text=True, encoding="utf-8")
        if proc.returncode != 0:
            print(f"MISSING  {full}: {proc.stderr.strip()[:80]}")
            continue
        r = json.loads(proc.stdout)
        row = {"repo": r["full_name"], "requested": full, "slug": slug(r["full_name"]), "category": category,
               "data_class": DATA_CLASS_ALIASES.get(data_class, data_class), "default_branch": r["default_branch"],
               "size_kb": r["size"], "language": r.get("language"), "stars": r.get("stargazers_count"),
               "archived": r.get("archived"), "html_url": r["html_url"], "description": (r.get("description") or "")[:160],
               "pushed_at": r.get("pushed_at")}
        row["skip"] = "too large" if r["size"] > MAX_SIZE_KB else None
        flag = f"SKIP({row['skip']})" if row["skip"] else "ok"
        print(f"{flag:<16} {row['repo']:<48} {row['language'] or '-':<12} {row['size_kb'] / 1024:7.1f} MB  *{row['stars']}")
        rows.append(row)
    (OUT / "manifest.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    ok = [r for r in rows if not r["skip"]]
    print(f"\n{len(ok)} usable / {len(rows)} resolved / {len(REPOS)} requested")


def _manifest() -> list[dict]:
    return [r for r in json.loads((OUT / "manifest.json").read_text(encoding="utf-8")) if not r["skip"]]


def _fetch_one(row: dict) -> str:
    target = OUT / "src" / row["slug"]
    if target.exists() and any(target.iterdir()):
        return f"cached  {row['repo']}"
    url = f"https://codeload.github.com/{row['repo']}/zip/refs/heads/{row['default_branch']}"
    with urllib.request.urlopen(url, timeout=600) as resp:
        data = resp.read()
    tmp = OUT / "src" / f"_tmp_{row['slug']}"
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        root = z.namelist()[0].split("/")[0]
        z.extractall(tmp)
    (tmp / root).rename(target)
    tmp.rmdir()
    (target / ".atlas-commit").write_text(row["default_branch"], encoding="utf-8")
    return f"fetched {row['repo']} ({len(data) / 1e6:.1f} MB zip)"


def fetch(jobs: int) -> None:
    (OUT / "src").mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(_fetch_one, r): r for r in _manifest()}
        for f in as_completed(futs):
            try:
                print(f.result(), flush=True)
            except Exception as exc:  # keep going; a failed fetch is just a smaller atlas
                print(f"FAILED  {futs[f]['repo']}: {exc}", flush=True)


def _scan_one(row: dict, python: str) -> str:
    src = OUT / "src" / row["slug"]
    dest = OUT / "scans" / row["slug"]
    if (dest / "result.json").exists():
        return f"cached  {row['repo']}"
    if not src.exists():
        return f"no-src  {row['repo']}"
    dest.mkdir(parents=True, exist_ok=True)
    cfg = dest / "ecdat.yaml"
    cfg.write_text(
        f"name: {row['slug']}\n"
        "params: {z_year: 2041, engineers: 4, months: 6, profile: enterprise, now_year: 2026}\n"
        "targets:\n"
        f"  - {{kind: dir, path: '{src.as_posix()}', name: '{row['repo']}', zone: internal, data_class: {row['data_class']}}}\n",
        encoding="utf-8")
    t0 = time.time()
    try:
        proc = subprocess.run([python, "-m", "ecdat.cli", "scan", "-c", str(cfg), "-o", str(dest)], cwd=ROOT,
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=SCAN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        (dest / "FAILED.txt").write_text(f"timeout after {SCAN_TIMEOUT_S}s", encoding="utf-8")
        return f"TIMEOUT {row['repo']}"
    (dest / "scan.log").write_text(proc.stdout[-20000:] + "\n--- stderr ---\n" + proc.stderr[-20000:], encoding="utf-8")
    if proc.returncode != 0 or not (dest / "result.json").exists():
        (dest / "FAILED.txt").write_text(proc.stderr[-4000:], encoding="utf-8")
        return f"FAILED  {row['repo']} (exit {proc.returncode})"
    return f"scanned {row['repo']} in {time.time() - t0:.0f}s"


MIN_FREE_BYTES = 900_000_000


def _wait_for_disk() -> None:
    while shutil.disk_usage(OUT).free < MIN_FREE_BYTES:
        print(f"  low disk ({shutil.disk_usage(OUT).free / 1e9:.2f} GB free), waiting...", flush=True)
        time.sleep(20)


def _run_one(row: dict, python: str) -> str:
    """fetch -> scan -> delete source. Keeps disk usage flat: only the CBOM outputs stay."""
    if (OUT / "scans" / row["slug"] / "result.json").exists():
        return f"cached  {row['repo']}"
    _wait_for_disk()
    try:
        _fetch_one(row)
    except Exception as exc:
        (OUT / "scans" / row["slug"]).mkdir(parents=True, exist_ok=True)
        (OUT / "scans" / row["slug"] / "FAILED.txt").write_text(f"fetch: {exc}", encoding="utf-8")
        return f"FETCH-FAILED {row['repo']}: {exc}"
    try:
        return _scan_one(row, python)
    finally:
        shutil.rmtree(OUT / "src" / row["slug"], ignore_errors=True)


def run(jobs: int) -> None:
    python = sys.executable
    for d in ("src", "scans"):
        (OUT / d).mkdir(parents=True, exist_ok=True)
    rows = sorted(_manifest(), key=lambda r: r["size_kb"])
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(_run_one, r, python): r for r in rows}
        for i, f in enumerate(as_completed(futs), 1):
            try:
                msg = f.result()
            except Exception as exc:
                msg = f"ERROR   {futs[f]['repo']}: {exc}"
            print(f"[{i}/{len(rows)}] {msg}  ({shutil.disk_usage(OUT).free / 1e9:.2f} GB free)", flush=True)


def scan(jobs: int) -> None:
    python = sys.executable
    (OUT / "scans").mkdir(parents=True, exist_ok=True)
    rows = sorted(_manifest(), key=lambda r: r["size_kb"])
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(_scan_one, r, python): r for r in rows}
        for i, f in enumerate(as_completed(futs), 1):
            print(f"[{i}/{len(rows)}] {f.result()}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["verify", "fetch", "scan", "run", "aggregate"])
    ap.add_argument("-j", "--jobs", type=int, default=3)
    a = ap.parse_args()
    if a.step == "verify":
        verify()
    elif a.step == "fetch":
        fetch(a.jobs)
    elif a.step == "scan":
        scan(a.jobs)
    elif a.step == "run":
        run(a.jobs)
    else:
        from atlas_aggregate import aggregate  # noqa: PLC0415
        aggregate(OUT, CATEGORIES)


if __name__ == "__main__":
    main()
