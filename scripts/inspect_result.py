"""Quick human-readable digest of a result.json (used for REAL_RUNS.md and demos)."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def main(path: str) -> None:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    print(f"# {d['name']}  ({len(d['assets'])} assets)  tiers={d['stats'].get('tiers')}  CERT-In={d['stats'].get('certin', {}).get('overall_pct')}%")
    print("per collector:", d["stats"]["collectors"]["per_collector"])
    for a in d["assets"]:
        if a["asset_type"] == "protocol" and a["evidence"][0]["location"].startswith(("tls://", "ssh://")):
            p = a["props"]
            print(f"- {a['evidence'][0]['location']}: versions={p.get('versions')} negotiated={(p.get('negotiated') or {}).get('cipher_suite')} "
                  f"kex_group={p.get('kex_group')} pq_kex={p.get('pq_kex')} reachable={p.get('reachable')} "
                  f"ssh_kex={p.get('kex')} err={(p.get('error') or '')[:80]} tier={a['risk']['tier']}")
        if a["asset_type"] == "certificate" and a["evidence"][0]["location"].startswith("tls://"):
            pr = a["props"]
            print(f"    cert {a['name']}: {pr.get('public_key_algorithm')}-{pr.get('key_size')} {pr.get('curve') or ''} sig={pr.get('signature_hash')} issuer={pr.get('issuer', '')[:60]}")
    by_comp = Counter(a["component"] for a in d["assets"])
    print("assets per component:", dict(by_comp))
    print("top of plan:")
    for i, it in enumerate(d["plan"]["items"][:8], 1):
        print(f"  {i}. {it.get('name')} [{it.get('component')}] {it.get('tier')} -> {it.get('target')} ({it.get('effort_weeks')} wk)")
    tiers_by_comp = {}
    for a in d["assets"]:
        tiers_by_comp.setdefault(a["component"], Counter())[a["risk"]["tier"]] += 1
    for c, t in tiers_by_comp.items():
        print(f"  {c}: {dict(t)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "out/zoo/result.json")
