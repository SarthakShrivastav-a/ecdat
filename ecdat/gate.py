"""CI gate: diff a current CBOM against a baseline CBOM and fail on newly introduced quantum-vulnerable crypto.
Policies:
  no-new-vulnerable  fail if a vulnerable asset exists now that was not in the baseline (existing debt grandfathered)
  no-vulnerable      fail if any vulnerable asset exists at all
  dst-m2             DST India milestone M2 ("no new classical-only deployments"): fail on new broken (Shor) assets in
                     external-facing components, or any new classical-only key exchange without a hybrid alternative"""
from __future__ import annotations

from dataclasses import dataclass, field

VULNERABLE = {"broken", "legacy-broken", "weakened"}


def _props(comp: dict) -> dict:
    return {p["name"]: p.get("value") for p in comp.get("properties", []) or []}


def _identity(comp: dict) -> tuple:
    p = _props(comp)
    occ = (comp.get("evidence") or {}).get("occurrences") or [{}]
    loc = occ[0].get("location", "")
    return (p.get("ecdat:component"), comp.get("name"), loc.split("#")[0])


def _assets(bom: dict) -> dict[tuple, dict]:
    out = {}
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        p = _props(c)
        if p.get("ecdat:usage") in ("test", "comment"):
            continue
        out[_identity(c)] = {"name": c.get("name"), "component": p.get("ecdat:component"), "quantum_class": p.get("ecdat:quantum_class"),
                             "tier": p.get("ecdat:tier"), "exposure": p.get("ecdat:exposure"), "usage": p.get("ecdat:usage"),
                             "location": _identity(c)[2], "primitive": ((c.get("cryptoProperties") or {}).get("algorithmProperties") or {}).get("primitive"),
                             "recommendation": p.get("ecdat:recommendation"), "bom_ref": c.get("bom-ref")}
    return out


@dataclass
class GateResult:
    passed: bool
    policy: str
    new_vulnerable: list = field(default_factory=list)
    all_vulnerable: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    added_safe: list = field(default_factory=list)
    summary_md: str = ""


def compare(baseline: dict, current: dict, policy: str = "no-new-vulnerable") -> GateResult:
    base, cur = _assets(baseline), _assets(current)
    new_keys = [k for k in cur if k not in base]
    removed = [base[k] for k in base if k not in cur]
    is_vuln = lambda a: (a.get("quantum_class") in VULNERABLE) and a.get("usage") != "non-security"
    new_vuln = [cur[k] for k in new_keys if is_vuln(cur[k])]
    added_safe = [cur[k] for k in new_keys if not is_vuln(cur[k])]
    all_vuln = [a for a in cur.values() if is_vuln(a)]
    if policy == "no-vulnerable":
        offenders = all_vuln
    elif policy == "dst-m2":
        offenders = [a for a in new_vuln if (a.get("quantum_class") == "broken" and a.get("exposure") == "external")
                     or (a.get("primitive") in ("key-agree", "kem", "pke") and a.get("quantum_class") == "broken")]
    else:
        offenders = new_vuln
    passed = not offenders
    lines = [f"## ECDAT CI gate: {'PASS' if passed else 'FAIL'}  (policy: {policy})", "",
             f"- assets now: {len(cur)}  baseline: {len(base)}  new: {len(new_keys)}  removed: {len(removed)}",
             f"- quantum-vulnerable now: {len(all_vuln)}  newly introduced: {len(new_vuln)}", ""]
    if offenders:
        lines += ["### Blocking findings", ""]
        for a in offenders:
            lines.append(f"- **{a['name']}** in `{a['component']}` at `{a['location']}` ({a['quantum_class']}, tier {a['tier']}) -> replace with {a.get('recommendation') or 'a PQC/hybrid alternative'}")
        lines.append("")
    if removed:
        lines += ["### Removed since baseline (good)", ""] + [f"- {a['name']} in `{a['component']}` at `{a['location']}`" for a in removed[:20]] + [""]
    if added_safe:
        lines += [f"### New quantum-safe or non-security assets: {len(added_safe)}", ""]
    lines += ["_Existing debt is grandfathered under no-new-vulnerable; DST M2 blocks new classical-only deployments._"]
    return GateResult(passed=passed, policy=policy, new_vulnerable=new_vuln, all_vulnerable=all_vuln, removed=removed,
                      added_safe=added_safe, summary_md="\n".join(lines) + "\n")
