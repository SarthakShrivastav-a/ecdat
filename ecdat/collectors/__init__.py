"""Collector registry. Every collector implements Collector.collect(target, kb) -> list[RawFinding]."""
from __future__ import annotations

import time

from typing import Callable

from ecdat.collectors.base import Collector, Target
from ecdat.collectors.binary import BinaryCollector
from ecdat.collectors.certificate import CertificateCollector
from ecdat.collectors.container import ContainerCollector
from ecdat.collectors.dependency import DependencyCollector
from ecdat.collectors.opengrep import OpenGrepCollector
from ecdat.collectors.pcap import PcapCollector
from ecdat.collectors.protocol import ProtocolCollector
from ecdat.collectors.source import SourceCollector
from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding

REGISTRY: dict[str, type[Collector]] = {
    "source": SourceCollector, "opengrep": OpenGrepCollector, "dependency": DependencyCollector,
    "certificate": CertificateCollector, "binary": BinaryCollector, "container": ContainerCollector,
    "protocol": ProtocolCollector, "pcap": PcapCollector,
}


def collectors_for(target: Target, enabled: set[str] | None = None) -> list[Collector]:
    out = []
    for name, cls in REGISTRY.items():
        if enabled is not None and name not in enabled:
            continue
        inst = cls()
        if target.kind in inst.kinds and inst.available():
            out.append(inst)
    return out


def run_collectors(targets: list[Target], kb: KnowledgeBase, enabled: set[str] | None = None,
                   progress: Callable[[str, str, int], None] | None = None) -> tuple[list[RawFinding], dict]:
    """Run every applicable collector on every target. Returns (findings, stats)."""
    findings: list[RawFinding] = []
    stats: dict = {"per_collector": {}, "per_target": {}, "errors": []}
    for t in targets:
        n_target = 0
        for coll in collectors_for(t, enabled):
            if progress:
                progress(t.name, coll.name, None, None, "start")
            t_started = time.monotonic()
            failed = False
            try:
                fs = coll.collect(t, kb)
            except Exception as exc:
                stats["errors"].append({"target": t.name, "collector": coll.name, "error": str(exc)[:300]})
                fs, failed = [], True
            for f in fs:
                f.context.setdefault("zone", t.zone)
            findings += fs
            n_target += len(fs)
            stats["per_collector"][coll.name] = stats["per_collector"].get(coll.name, 0) + len(fs)
            if progress:
                progress(t.name, coll.name, len(fs), round(time.monotonic() - t_started, 2), "done", failed)
        stats["per_target"][t.name] = n_target
    stats["total_findings"] = len(findings)
    return findings, stats
