"""Scan configuration: YAML -> ScanConfig(name, targets, params, enabled collectors, output)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ecdat.collectors.base import Target
from ecdat.model import ScanParams

KINDS = {"dir", "repo", "image", "certs", "endpoints", "pcap", "binary"}


@dataclass
class ScanConfig:
    name: str = "ecdat-scan"
    targets: list[Target] = field(default_factory=list)
    params: ScanParams = field(default_factory=ScanParams)
    collectors: set[str] | None = None          # None = all applicable
    base_dir: Path = field(default_factory=Path.cwd)

    def to_dict(self) -> dict:
        return {"name": self.name, "targets": [t.to_dict() for t in self.targets], "params": self.params.to_dict(),
                "collectors": sorted(self.collectors) if self.collectors else None}


def _resolve(base: Path, p: str) -> str:
    if not p:
        return p
    if "://" in p or p.startswith(("registry:", "docker.io/", "ghcr.io/")):
        return p
    path = Path(p)
    return str(path if path.is_absolute() else (base / path))


def load(path: str | Path) -> ScanConfig:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    base = path.parent
    return from_dict(data, base)


def from_dict(data: dict, base: Path | None = None) -> ScanConfig:
    base = base or Path.cwd()
    params = ScanParams(**{k: v for k, v in (data.get("params") or {}).items() if k in ScanParams.__dataclass_fields__})
    targets = []
    for i, t in enumerate(data.get("targets") or []):
        kind = t.get("kind", "dir")
        if kind not in KINDS:
            raise ValueError(f"target {i}: unknown kind {kind!r} (expected one of {sorted(KINDS)})")
        props = dict(t.get("props") or {})
        if "endpoints" in t:
            props["endpoints"] = list(t["endpoints"])
        if "passwords" in t:
            props["passwords"] = list(t["passwords"])
        if not params.use_external_tools:
            props.update({"use_theia": False, "use_syft": False, "use_tshark": False, "use_cryptolyzer": False})
        targets.append(Target(kind=kind, path=_resolve(base, t.get("path", "")) if kind != "endpoints" or t.get("path") else "",
                              name=t.get("name") or f"target-{i + 1}", zone=t.get("zone", "internal"),
                              data_class=t.get("data_class"), criticality=t.get("criticality"), props=props))
    collectors = set(data["collectors"]) if data.get("collectors") else None
    return ScanConfig(name=data.get("name", "ecdat-scan"), targets=targets, params=params, collectors=collectors, base_dir=base)
