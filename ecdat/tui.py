"""How a scan looks while it runs.

The pipeline emits structured progress; this renders it as the four phases the rest of the project
talks about - DISCOVER, RECONCILE, ANALYSE, DECIDE - then the files it wrote. It is the same story
on a laptop, in CI (no ANSI, no live redraw) and in the screenshots in the README.

Set ECDAT_RECORD_SVG=path/to/scan.svg to save the whole session as an SVG terminal window.
"""
from __future__ import annotations

import os
import time
from typing import Any

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

TIER_STYLE = {"EXPOSED": "bold red", "ACT_NOW": "bold yellow", "MONITOR": "cyan", "SAFE": "green"}
TIER_LABEL = {"EXPOSED": "already exposed", "ACT_NOW": "act now", "MONITOR": "monitor", "SAFE": "safe"}
SPINNER = "|/-\\"


def _n(v: Any, dash: str = "-") -> str:
    return dash if v is None else f"{v:,}" if isinstance(v, int) else str(v)


class ScanReporter:
    """Renders one scan. Call header(), pass on_progress to the pipeline, then summary()."""

    def __init__(self, console: Console, cfg, version: str) -> None:
        self.c = console
        self.cfg = cfg
        self.version = version
        self.rows: list[dict] = []          # one per (target, collector)
        self.live: Live | None = None
        self.collect_closed = False
        self.t0 = time.monotonic()
        self.frame = 0

    # ------------------------------------------------------------------ chrome
    def header(self) -> None:
        p = self.cfg.params
        targets = Table.grid(padding=(0, 2))
        targets.add_column(style="dim", no_wrap=True)
        targets.add_column()
        for t in self.cfg.targets:
            targets.add_row(t.kind, f"[cyan]{t.name}[/]  [dim]{getattr(t, 'zone', '') or ''}[/]")
        meta = (f"[dim]quantum year Z[/] [bold]{p.z_year}[/]   [dim]profile[/] [bold]{p.profile}[/]   "
                f"[dim]budget[/] [bold]{p.engineers}[/] engineers x [bold]{p.months}[/] months   "
                f"[dim]network[/] [bold]{'off' if not p.use_external_tools else 'local tools only'}[/]")
        self.c.print(Panel(Group(targets, Text(), Text.from_markup(meta)),
                           title=f"[bold]ECDAT {self.version}[/]  ·  {self.cfg.name}",
                           subtitle="[dim]cryptographic discovery, CBOM, quantum risk, migration plan[/]",
                           border_style="yellow", padding=(1, 2)))

    def phase(self, n: int, title: str, detail: str = "") -> None:
        self.c.print()
        self.c.print(Rule(f"[bold yellow]{n}[/] [bold]{title}[/]" + (f"  [dim]{detail}[/]" if detail else ""),
                          style="yellow", align="left"))

    # ------------------------------------------------------------------ phase 1, live
    def _table(self) -> Table:
        t = Table.grid(padding=(0, 3))
        t.add_column(width=2)
        t.add_column("collector", style="bold", no_wrap=True, width=22)
        t.add_column("target", style="dim", no_wrap=True, width=22)
        t.add_column("findings", justify="right", width=9)
        t.add_column("time", justify="right", style="dim", width=7)
        for r in self.rows:
            if r["done"]:
                mark = Text("OK", style="green") if not r["error"] else Text("!!", style="red")
                found = Text(_n(r["findings"]), style="bold" if r["findings"] else "dim")
                secs = f"{r['seconds']:.1f}s" if r["seconds"] is not None else ""
            else:
                mark = Text(SPINNER[self.frame % 4], style="yellow")
                found = Text("...", style="dim")
                secs = ""
            t.add_row(mark, r["collector"], r["target"], found, secs)
        return t

    def start_collect(self) -> None:
        if self.c.is_terminal:
            # transient: the per-run rows stream while it works, then collapse into the summary below
            self.live = Live(self._table(), console=self.c, refresh_per_second=12, transient=True)
            self.live.start()

    def stop_collect(self) -> None:
        """Close phase 1 once, leaving one row per collector rather than one per (target, collector)."""
        if self.collect_closed:
            return
        if self.live:
            self.live.update(self._table())
            self.live.stop()
            self.live = None
        if not self.rows:
            return
        self.collect_closed = True
        agg: dict[str, dict] = {}
        for r in self.rows:
            a = agg.setdefault(r["collector"], {"runs": 0, "findings": 0, "seconds": 0.0, "errors": 0})
            a["runs"] += 1
            a["findings"] += r["findings"] or 0
            a["seconds"] += r["seconds"] or 0.0
            a["errors"] += 1 if r["error"] else 0
        t = Table.grid(padding=(0, 3))
        t.add_column(width=2)
        t.add_column("collector", style="bold", no_wrap=True, width=14)
        t.add_column("targets", justify="right", style="dim", width=8)
        t.add_column("findings", justify="right", width=9)
        t.add_column("time", justify="right", style="dim", width=7)
        for name, a in sorted(agg.items(), key=lambda kv: -kv[1]["findings"]):
            mark = Text("!!", style="red") if a["errors"] else Text("OK", style="green")
            t.add_row(mark, name, str(a["runs"]),
                      Text(_n(a["findings"]), style="bold" if a["findings"] else "dim"),
                      f"{a['seconds']:.1f}s")
        self.c.print(t)
        total = sum(a["findings"] for a in agg.values())
        self.c.print(f"  [dim]{len(agg)} collectors over {len(self.rows)} target runs -> "
                     f"[/][bold]{total:,}[/] [dim]raw findings, each with file:line and a confidence[/]")

    def _touch(self, target: str, collector: str) -> dict:
        for r in self.rows:
            if r["target"] == target and r["collector"] == collector:
                return r
        r = {"target": target, "collector": collector, "findings": None, "seconds": None,
             "done": False, "error": False}
        self.rows.append(r)
        return r

    # ------------------------------------------------------------------ the pipeline's callback
    def on_progress(self, stage: str, msg: str, **data: Any) -> None:
        if stage == "collect-start":
            self._touch(data["target"], data["collector"])
        elif stage == "collect":
            r = self._touch(data["target"], data["collector"])
            r.update(findings=data.get("findings"), seconds=data.get("seconds"), done=True,
                     error=bool(data.get("error")))
        elif stage in ("merge", "analyse", "done"):
            return                            # these get their own phase blocks in cli.scan
        self.frame += 1
        if self.live:
            self.live.update(self._table())

    # ------------------------------------------------------------------ results
    def tiers(self, stats: dict) -> None:
        tiers = stats.get("tiers") or {}
        total = max(1, sum(tiers.values()))
        t = Table.grid(padding=(0, 2))
        t.add_column(width=16)
        t.add_column(justify="right", width=6)
        t.add_column(width=34)
        t.add_column(style="dim")
        for k in ("EXPOSED", "ACT_NOW", "MONITOR", "SAFE"):
            n = tiers.get(k, 0)
            bar = "#" * max(0, round(30 * n / total))
            t.add_row(Text(TIER_LABEL[k], style=TIER_STYLE[k]), Text(str(n), style=TIER_STYLE[k]),
                      Text(bar, style=TIER_STYLE[k]), f"{100 * n / total:.0f}%")
        self.c.print(t)

    def summary(self, result, files: dict) -> None:
        s = result.stats
        c = s.get("certin") or {}
        plan = result.plan or {}
        self.phase(5, "OUTPUTS", "every artefact a reviewer can open")
        t = Table.grid(padding=(0, 3))
        t.add_column(style="bold", no_wrap=True, width=12)
        t.add_column(style="cyan")
        for k, v in files.items():
            t.add_row(k, str(v))
        self.c.print(t)

        signed = files.get("cbom_sig") or files.get("signature")
        lines = [
            f"[dim]assets[/] [bold]{len(result.assets):,}[/] across [bold]{s.get('components')}[/] components   "
            f"[dim]evidence[/] [bold]{s.get('total_findings', s.get('collectors', {}).get('total_findings', 0)):,}[/] findings",
            f"[dim]CycloneDX 1.7 valid[/] [bold]{'yes' if s.get('cbom_valid', True) else 'NO'}[/]   "
            f"[dim]CERT-In Table 9[/] [bold]{c.get('overall_pct')}%[/]   "
            f"[dim]signed[/] [bold]{'ML-DSA-65' if signed else 'no'}[/]",
            f"[dim]plan[/] removes [bold]{plan.get('covered_pct', 0)}%[/] of quantum risk in "
            f"[bold]{plan.get('used_weeks', 0)}[/] engineer-weeks at Z=[bold]{result.params.z_year}[/]",
            f"[dim]took[/] [bold]{s.get('duration_s')}s[/]",
        ]
        self.c.print(Panel("\n".join(lines), border_style="green", padding=(1, 2),
                           title="[bold green]scan complete[/]"))
        if signed:
            self.c.print(f"[dim]verify it yourself:[/] ecdat verify {files.get('cbom')} --pubkey <key>.pub")

    # ------------------------------------------------------------------ optional SVG capture
    @staticmethod
    def wants_svg() -> str | None:
        return os.environ.get("ECDAT_RECORD_SVG") or None

    def save_svg(self, path: str) -> None:
        self.c.save_svg(path, title=f"ecdat scan -c {self.cfg.name}.yaml", clear=False)
