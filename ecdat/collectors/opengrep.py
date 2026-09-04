"""OpenGrep engine (optional): runs the semgrep-rules crypto audit tree for a second, independent opinion.
Findings corroborate the tree-sitter engine; they never replace it."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from ecdat import tools
from ecdat.collectors.base import Collector, Target, path_context, rel
from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding

RULE_HINTS = [
    (r"desede|3des|triple[-_]?des|tripledes", "3DES"), (r"\bdes\b|des-is|des_", "DES"), (r"md5", "MD5"),
    (r"sha-?1\b|sha1", "SHA-1"), (r"rc4|arc4|arcfour", "RC4"), (r"blowfish", "Blowfish"), (r"rsa", "RSA"),
    (r"\bdsa\b", "DSA"), (r"ecdsa|ec-key|ec_key|elliptic", "ECDSA"), (r"\baes\b|aes-", "AES"),
    (r"ecb", "AES"), (r"tls|ssl", "TLS"),
]
KEY_SIZE_RE = re.compile(r"(?:key_size|modulusLength|bits|keysize|key-size)\s*[=:(]\s*(\d{3,5})|\b(512|768|1024|1536|2048|3072|4096)\b")


class OpenGrepCollector(Collector):
    name = "opengrep"
    kinds = {"dir", "repo", "image"}

    def available(self) -> bool:
        return tools.find("opengrep") is not None and tools.RULES_DIR.exists()

    def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]:
        if not self.available():
            return []
        exe = tools.find("opengrep")
        root = Path(target.path)
        # Run from inside the target and scan "." so OpenGrep's default excludes (test/, fixtures/ ...) only
        # apply to sub-directories, never to the target path itself.
        cwd = root if root.is_dir() else root.parent
        what = "." if root.is_dir() else root.name
        cmd = [str(exe), "scan", "--config", str(tools.RULES_DIR), "--json", "--quiet", "--timeout", "60", what]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, encoding="utf-8", errors="replace",
                                  cwd=str(cwd))
        except (subprocess.TimeoutExpired, OSError):
            return []
        raw = proc.stdout or ""
        i = raw.find("{")
        if i < 0:
            return []
        try:
            data = json.loads(raw[i:])
        except json.JSONDecodeError:
            return []
        out: list[RawFinding] = []
        for r in data.get("results", []):
            check = r.get("check_id", "")
            rule = check.split(".")[-1]
            path = Path(r.get("path", ""))
            if not path.is_absolute():
                path = cwd / path
            location = rel(path, root) if root.is_dir() else path.name
            if target.props.get("location_prefix"):
                location = target.props["location_prefix"] + location
            line = int(r.get("start", {}).get("line", 0) or 0)
            extra = r.get("extra", {})
            snippet = (extra.get("lines") or "").strip()[:200]
            name = self._algorithm_for(rule, snippet, kb)
            if not name:
                continue
            props = {"rule": check, "message": (extra.get("message") or "")[:300], "api": "opengrep",
                     "severity": extra.get("severity")}
            m = KEY_SIZE_RE.search(snippet)
            if m:
                ks = int(m.group(1) or m.group(2))
                props["key_size"] = ks
                sized = kb.canonicalise(name, ks)
                if sized:
                    name = sized
            asset_type = "protocol" if name == "TLS" else "algorithm"
            if asset_type == "protocol":
                props["type"] = "tls"
            ctx = path_context(location)
            ctx["zone"] = target.zone
            meta = extra.get("metadata", {}) or {}
            if meta.get("cwe"):
                props["cwe"] = meta["cwe"] if isinstance(meta["cwe"], list) else [meta["cwe"]]
            out.append(RawFinding("opengrep", asset_type, name, location, line, snippet, "medium", target.name, props, ctx))
        return out

    @staticmethod
    def _algorithm_for(rule: str, snippet: str, kb: KnowledgeBase) -> str | None:
        low = rule.lower()
        # 1) explicit token in the matched line wins (most precise)
        for tok in re.findall(r"[A-Za-z0-9_\-/]{3,}", snippet):
            canon = kb.canonicalise(tok)
            if canon and canon not in ("TLS", "SSH", "IPsec"):
                return canon
        # 2) rule-id hint
        for pat, canon in RULE_HINTS:
            if re.search(pat, low):
                return canon
        return None
