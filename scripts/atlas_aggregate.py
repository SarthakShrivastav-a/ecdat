"""Roll per-repo ECDAT scans up into the CBOM Atlas numbers (out/atlas/atlas.json + atlas.md).

"Observed" means found in the repo's own code, config, certificates or binaries. Algorithms a dependency merely
*can* provide are counted separately (library_capability_only) and never inflate the headline numbers.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

PQC_RE = re.compile(r"(?<![A-Z0-9])(ML-?KEM|ML-?DSA|SLH-?DSA|KYBER|DILITHIUM|SPHINCS\+?|FALCON|FN-DSA|HQC|X25519MLKEM768|"
                    r"SECP256R1MLKEM768|FRODO(KEM)?|NTRU(PRIME)?|SNTRUP761|CLASSIC-MCELIECE|BIKE|XMSS|LMS)(?![A-Z])")
ALGO_TYPES = ("algorithm", "protocol", "related-crypto-material")


def _observed(a: dict) -> bool:
    ctx = a.get("context") or {}
    return not (ctx.get("from_library_only") and not ctx.get("corroborated"))


def _production(a: dict) -> bool:
    return (a.get("context") or {}).get("usage") not in ("test", "comment", "non-security")


def _is_pqc(a: dict) -> bool:
    if a.get("asset_type") not in ALGO_TYPES:
        return False
    text = " ".join(str(a.get(k) or "") for k in ("name", "family", "parameter_set")).upper()
    return bool(PQC_RE.search(text))


def _alg_label(a: dict) -> str:
    return str(a.get("family") or a.get("name"))


def _cert_key(a: dict) -> str:
    p = a.get("props") or {}
    k = str(p.get("public_key_algorithm") or p.get("key_algorithm") or a.get("family") or "").upper()
    return "RSA" if "RSA" in k else "ECDSA" if ("EC" in k and "ED" not in k) else "EdDSA" if "ED" in k else (k or "other")


def repo_summary(row: dict, result: dict) -> dict:
    assets = result["assets"]
    obs = [a for a in assets if _observed(a)]
    prod = [a for a in obs if _production(a)]
    tiers = Counter((a.get("risk") or {}).get("tier") for a in obs)
    qc = lambda a: (a.get("risk") or {}).get("quantum_class")  # noqa: E731
    algo = [a for a in prod if a.get("asset_type") in ALGO_TYPES]
    shor = sorted({_alg_label(a) for a in algo if qc(a) == "broken"})
    legacy = sorted({_alg_label(a) for a in algo if qc(a) == "legacy-broken"})
    pqc = sorted({_alg_label(a) for a in obs if _is_pqc(a)})
    certs = [a for a in obs if a.get("asset_type") == "certificate"]
    cert_keys = Counter(_cert_key(a) for a in certs)
    exposed = [a for a in obs if (a.get("risk") or {}).get("tier") == "EXPOSED"]
    stats = result["stats"]
    plan = result.get("plan") or {}
    top = (plan.get("items") or [None])[0]
    return {
        "repo": row["repo"], "slug": row["slug"], "category": row["category"], "language": row.get("language"),
        "stars": row.get("stars"), "data_class": row["data_class"], "url": row["html_url"],
        "assets": len(assets), "observed": len(obs), "library_capability_only": len(assets) - len(obs),
        "tiers": {t: tiers.get(t, 0) for t in ("EXPOSED", "ACT_NOW", "MONITOR", "SAFE")},
        "certificates": len(certs), "certificate_keys": dict(cert_keys),
        "shor_broken_in_production": shor, "legacy_broken_in_production": legacy, "pqc_present": pqc,
        "exposed": [{"name": a["name"], "location": (a.get("evidence") or [{}])[0].get("location"),
                     "reason": ((a.get("risk") or {}).get("reasons") or [""])[0]} for a in exposed][:5],
        "certin_pct": (stats.get("certin") or {}).get("overall_pct"), "cbom_valid": stats.get("cbom_valid"),
        "findings": (stats.get("collectors") or {}).get("total_findings"), "duration_s": stats.get("duration_s"),
        "per_collector": (stats.get("collectors") or {}).get("per_collector"),
        "plan_top": {"name": top["name"], "target": top.get("target"), "tier": top["tier"], "weeks": top["effort_weeks"]} if top else None,
        "signed": Path(result.get("_dir", "")).joinpath("cbom.json.mldsa65.sig").exists() if result.get("_dir") else None,
    }


def _pct(n: int, d: int) -> float:
    return round(100.0 * n / d, 1) if d else 0.0


def roll(repos: list[dict]) -> dict:
    n = len(repos)
    alg = Counter(x for r in repos for x in r["shor_broken_in_production"] + r["legacy_broken_in_production"])
    return {
        "repos": n,
        "assets": sum(r["assets"] for r in repos),
        "observed_assets": sum(r["observed"] for r in repos),
        "library_capability_only": sum(r["library_capability_only"] for r in repos),
        "findings": sum(r["findings"] or 0 for r in repos),
        "tiers": {t: sum(r["tiers"][t] for r in repos) for t in ("EXPOSED", "ACT_NOW", "MONITOR", "SAFE")},
        "repos_with_shor_broken_pct": _pct(sum(1 for r in repos if r["shor_broken_in_production"]), n),
        "repos_with_legacy_broken_pct": _pct(sum(1 for r in repos if r["legacy_broken_in_production"]), n),
        "repos_with_pqc_pct": _pct(sum(1 for r in repos if r["pqc_present"]), n),
        "repos_with_exposed": sum(1 for r in repos if r["tiers"]["EXPOSED"]),
        "cbom_valid_pct": _pct(sum(1 for r in repos if r["cbom_valid"]), n),
        "signed_pct": _pct(sum(1 for r in repos if r["signed"]), n),
        "certin_avg_pct": round(sum(r["certin_pct"] or 0 for r in repos) / n, 1) if n else 0.0,
        "scan_seconds_total": round(sum(r["duration_s"] or 0 for r in repos), 1),
        "scan_seconds_median": sorted(r["duration_s"] or 0 for r in repos)[n // 2] if n else 0,
        "top_vulnerable_algorithms": alg.most_common(12),
        "certificates": sum(r["certificates"] for r in repos),
        "certificate_keys": dict(sum((Counter(r["certificate_keys"]) for r in repos), Counter())),
    }


def aggregate(out: Path, categories: dict[str, str]) -> dict:
    manifest = {r["slug"]: r for r in json.loads((out / "manifest.json").read_text(encoding="utf-8"))}
    repos, failed = [], []
    for d in sorted((out / "scans").iterdir()):
        if not d.is_dir() or d.name not in manifest:
            continue
        res = d / "result.json"
        if not res.exists():
            failed.append({"repo": manifest[d.name]["repo"], "why": (d / "FAILED.txt").read_text(encoding="utf-8")[:200]
                           if (d / "FAILED.txt").exists() else "incomplete"})
            continue
        result = json.loads(res.read_text(encoding="utf-8"))
        result["_dir"] = str(d)
        repos.append(repo_summary(manifest[d.name], result))
    by_cat = {c: {"label": label, **roll([r for r in repos if r["category"] == c])} for c, label in categories.items()}
    data = {"overall": roll(repos), "by_category": by_cat, "repos": repos, "failed": failed,
            "params": {"z_year": 2041, "profile": "enterprise", "budget": "4 engineers x 6 months"}}
    (out / "atlas.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    o = data["overall"]
    lines = ["# CBOM Atlas", "",
             f"{o['repos']} public repositories · {o['findings']} raw findings · {o['assets']} CBOM assets "
             f"({o['observed_assets']} observed in the code, {o['library_capability_only']} library capability only)",
             f"CBOMs schema-valid: {o['cbom_valid_pct']}% · ML-DSA-65 signed: {o['signed_pct']}% · CERT-In Table 9 avg: {o['certin_avg_pct']}%",
             f"Repos using Shor-broken crypto (RSA/ECC/DH) in production code: {o['repos_with_shor_broken_pct']}%",
             f"Repos using classically broken crypto (MD5/SHA-1/DES/3DES/RC4/short keys) in production: {o['repos_with_legacy_broken_pct']}%",
             f"Repos already using any post-quantum algorithm: {o['repos_with_pqc_pct']}%",
             f"Tiers (observed): {o['tiers']}", f"Scan time: total {o['scan_seconds_total']} s, median {o['scan_seconds_median']} s per repo",
             f"Most common vulnerable algorithms: {o['top_vulnerable_algorithms']}", "", "## By category", "",
             "| category | repos | observed assets | Shor-broken in prod | legacy-broken in prod | any PQC | EXPOSED repos | CERT-In avg |",
             "|---|---|---|---|---|---|---|---|"]
    for c, v in by_cat.items():
        lines.append(f"| {v['label']} | {v['repos']} | {v['observed_assets']} | {v['repos_with_shor_broken_pct']}% | "
                     f"{v['repos_with_legacy_broken_pct']}% | {v['repos_with_pqc_pct']}% | {v['repos_with_exposed']} | {v['certin_avg_pct']}% |")
    if failed:
        lines += ["", f"## Not scanned ({len(failed)})", ""] + [f"- {f['repo']}: {f['why'][:120]}" for f in failed]
    (out / "atlas.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return data
