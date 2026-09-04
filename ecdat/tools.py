"""Locate optional external engines. Every collector works without them; they add breadth/corroboration."""
from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GO_BIN = Path(os.environ.get("USERPROFILE", os.environ.get("HOME", ""))) / "go" / "bin"
WIRESHARK = Path(r"C:\Program Files\Wireshark")


def _tools_dirs() -> list[Path]:
    dirs = []
    env = os.environ.get("ECDAT_TOOLS_DIR")
    if env:
        dirs.append(Path(env))
    # ROOT/tools, then every ancestor's tools/ (worktrees nested under the main checkout find its tools/)
    for base in [ROOT, *ROOT.parents]:
        dirs.append(base / "tools")
    return dirs


def _first_existing(names: list[str]) -> Path | None:
    for d in _tools_dirs():
        for n in names:
            p = d / n
            if p.exists():
                return p
    return None


TOOLS_DIR = next((d for d in _tools_dirs() if (d / "findcrypt3.rules").exists()), ROOT / "tools")
RULES_DIR = TOOLS_DIR / "semgrep-crypto-rules"
FINDCRYPT_RULES = TOOLS_DIR / "findcrypt3.rules"

CANDIDATES = {
    "opengrep": lambda: _first_existing(["opengrep.exe", "opengrep"]),
    "syft": lambda: _first_existing(["syft.exe", "syft"]),
    "cbomkit-theia": lambda: next((p for p in [GO_BIN / "cbomkit-theia.exe", GO_BIN / "cbomkit-theia"] if p.exists()), None),
    "crane": lambda: next((p for p in [GO_BIN / "crane.exe", GO_BIN / "crane"] if p.exists()), None),
    "tshark": lambda: next((p for p in [WIRESHARK / "tshark.exe"] if p.exists()), None),
}
VERSION_ARGS = {
    "opengrep": ["--version"], "syft": ["version"], "cbomkit-theia": ["--help"],
    "crane": ["version"], "tshark": ["--version"],
}


@lru_cache(maxsize=None)
def find(name: str) -> Path | None:
    if os.environ.get("ECDAT_NO_EXTERNAL_TOOLS") == "1":
        return None
    p = CANDIDATES.get(name, lambda: None)()
    if p:
        return p
    w = shutil.which(name)
    return Path(w) if w else None


def version(name: str) -> str | None:
    p = find(name)
    if not p:
        return None
    try:
        out = subprocess.run([str(p)] + VERSION_ARGS.get(name, ["--version"]), capture_output=True,
                             text=True, timeout=30, encoding="utf-8", errors="replace")
        text = (out.stdout or out.stderr or "").strip().splitlines()
        for line in text:
            if any(ch.isdigit() for ch in line) and len(line) < 120:
                return line.strip()
        return text[0][:80] if text else "present"
    except Exception:
        return "present"


def versions() -> dict:
    out = {"ecdat": __import__("ecdat").__version__}
    for name in CANDIDATES:
        out[name] = version(name)
    try:
        import cyclonedx, cryptography, yara, lief, scapy, tree_sitter  # noqa
        out.update({"cyclonedx-python-lib": cyclonedx.__version__, "cryptography": cryptography.__version__,
                    "yara-python": yara.__version__, "lief": lief.__version__, "scapy": scapy.__version__,
                    "tree-sitter": tree_sitter.__version__})
    except Exception:
        pass
    return out
