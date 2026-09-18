"""Collector protocol and shared file helpers."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".idea", ".tox",
             "site-packages", ".mypy_cache", ".pytest_cache", "target", ".gradle"}
TEST_PARTS = {"test", "tests", "spec", "specs", "__tests__", "testdata", "mocks", "e2e"}
TEST_WORDS = {"test", "tests", "testing", "testutil", "testutils", "fixture", "fixtures", "integration_tests", "integrationtests"}
NOT_TEST = {"latest", "contest", "attest", "protest", "detest", "greatest", "fastest"}


def _is_test_dir(part: str) -> bool:
    """test/, but also caddytest/, certbot-compatibility-test/, certbot_integration_tests/, test-utils/ (not latest/)."""
    if part in TEST_PARTS:
        return True
    if part in NOT_TEST:
        return False
    words = [w for w in part.replace("-", "_").replace(".", "_").split("_") if w]
    return any(w in TEST_WORDS for w in words) or (part.isalnum() and part.endswith(("test", "tests")) and len(part) > 5)
VENDOR_PARTS = {"vendor", "vendors", "third_party", "thirdparty", "external", "node_modules", "deps", "contrib"}
BINARY_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"PK\x03\x04",
                b"\x00asm")
BINARY_EXTS = {".so", ".dll", ".exe", ".dylib", ".bin", ".a", ".o", ".jar", ".war", ".class", ".wasm", ".elf",
               ".ko", ".sys", ".efi", ".img", ".fw"}


@dataclass
class Target:
    kind: str                      # dir | repo | image | certs | endpoints | pcap | binary
    path: str
    name: str = "target"
    zone: str = "internal"         # internal | external
    data_class: str | None = None
    criticality: str | None = None
    props: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "path": self.path, "name": self.name, "zone": self.zone,
                "data_class": self.data_class, "criticality": self.criticality, "props": self.props}


class Collector:
    name: str = "base"
    kinds: set[str] = set()

    def available(self) -> bool:
        return True

    def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]:  # pragma: no cover
        raise NotImplementedError


def walk_files(root: str | Path, exts: set[str] | None = None, skip_dirs: set[str] = SKIP_DIRS,
               max_size: int = 20 * 1024 * 1024) -> Iterator[Path]:
    root = Path(root)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            p = Path(dirpath) / fn
            if exts and p.suffix.lower() not in exts:
                continue
            try:
                if p.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            yield p


def rel(path: Path, root: str | Path) -> str:
    try:
        return path.resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def path_context(path: str | Path) -> dict:
    parts = [p.lower() for p in Path(path).parts]
    name = Path(path).name.lower()
    is_test = any(_is_test_dir(p) for p in parts[:-1]) or name.startswith("test_") or name.endswith("_test.go") \
        or ".test." in name or ".spec." in name or name.endswith("test.java") or name.endswith("tests.py")
    is_vendored = any(p in VENDOR_PARTS for p in parts[:-1])
    is_example = any(p in {"example", "examples", "samples", "demo", "docs"} for p in parts[:-1])
    return {"is_test": bool(is_test), "is_vendored": bool(is_vendored), "is_example": bool(is_example)}


def is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTS:
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return any(head.startswith(m) for m in BINARY_MAGIC)


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
