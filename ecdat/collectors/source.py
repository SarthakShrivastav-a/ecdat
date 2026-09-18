"""Source collector: tree-sitter call-site detection driven by knowledge/source_patterns.yaml,
config-file directive parsing, comment scanning, and a regex fallback for other languages."""
from __future__ import annotations

import fnmatch
import re
from functools import lru_cache
from pathlib import Path

from ecdat.collectors.base import Collector, Target, path_context, read_text, rel, walk_files
from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding

# ------------------------------------------------------------------------------------------------
# tree-sitter setup
# ------------------------------------------------------------------------------------------------
CALL_TYPES = {
    "python": {"call"},
    "javascript": {"call_expression", "new_expression"},
    "java": {"method_invocation", "object_creation_expression"},
    "go": {"call_expression"},
    "c": {"call_expression"},
}
INT_TYPES = {"integer", "number", "decimal_integer_literal", "int_literal", "number_literal", "integer_literal"}
STR_TYPES = {"string", "string_literal", "interpreted_string_literal", "raw_string_literal", "template_string",
             "concatenated_string"}
COMMENT_TYPES = {"comment", "line_comment", "block_comment"}
IMPORT_TYPES = {"import_statement", "import_from_statement", "import_declaration", "import_spec",
                "preproc_include", "call_expression"}
PUNCT = {",", "(", ")", "{", "}", "[", "]", ":"}


@lru_cache(maxsize=None)
def _parser(lang: str):
    from tree_sitter import Language, Parser
    mod = {
        "python": "tree_sitter_python", "javascript": "tree_sitter_javascript", "java": "tree_sitter_java",
        "go": "tree_sitter_go", "c": "tree_sitter_c",
    }[lang]
    m = __import__(mod)
    return Parser(Language(m.language()))


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] in "\"'`" and s[-1] == s[0]:
        return s[1:-1]
    return s


# ------------------------------------------------------------------------------------------------
# parsers for algorithm strings
# ------------------------------------------------------------------------------------------------
_SIG_RE = re.compile(r"^(?P<hash>SHA\d{1,3}|SHA3-?\d{3}|MD5|MD2|NONE)with(?P<alg>RSA|ECDSA|DSA|RSAandMGF1|RSA/PSS|EdDSA|ML-DSA)", re.I)


def parse_java_transformation(s: str, kb: KnowledgeBase) -> dict:
    parts = s.split("/")
    alg = kb.canonicalise(parts[0]) if parts else None
    out = {"algorithm": alg, "raw": s}
    if len(parts) > 1:
        out["mode"] = parts[1].upper()
    if len(parts) > 2:
        out["padding"] = parts[2]
    m = re.match(r"^(AES|DES|Blowfish|ChaCha20)[_-]?(\d{3})?", parts[0], re.I)
    if m and m.group(2):
        out["key_size"] = int(m.group(2))
        out["algorithm"] = kb.canonicalise(m.group(1), int(m.group(2)))
    return out


def parse_java_signature(s: str, kb: KnowledgeBase) -> dict:
    m = _SIG_RE.match(s.replace(" ", ""))
    if m:
        hash_raw = m.group("hash")
        alg_raw = m.group("alg")
        alg = kb.canonicalise("RSA" if alg_raw.upper().startswith("RSA") else alg_raw)
        h = kb.canonicalise(hash_raw.replace("SHA", "SHA-", 1) if re.match(r"^SHA\d", hash_raw, re.I) else hash_raw)
        return {"algorithm": alg, "hash": h, "raw": s, "primitive": "signature"}
    return {"algorithm": kb.canonicalise(s), "raw": s, "primitive": "signature"}


def parse_cipher_name(s: str, kb: KnowledgeBase) -> dict:
    """node/openssl style: aes-256-gcm, aes-128-cbc, des-ede3-cbc, chacha20-poly1305, rc4"""
    low = s.lower()
    out = {"raw": s}
    m = re.match(r"^(aes|camellia|aria)[-_]?(\d{3})[-_]?([a-z0-9]+)?", low)
    if m:
        out["algorithm"] = kb.canonicalise(m.group(1), int(m.group(2)))
        out["key_size"] = int(m.group(2))
        if m.group(3):
            out["mode"] = m.group(3).upper()
        return out
    out["algorithm"] = kb.canonicalise(low)
    mm = re.search(r"-(cbc|gcm|ctr|ecb|ccm|ofb|cfb|xts)\b", low)
    if mm:
        out["mode"] = mm.group(1).upper()
    return out


SUITE_TOKENS = {
    "ECDHE": ("ECDH", "key-agree"), "ECDH": ("ECDH", "key-agree"), "DHE": ("DH", "key-agree"), "DH": ("DH", "key-agree"),
    "RSA": ("RSA", "pke"), "ECDSA": ("ECDSA", "signature"), "DSS": ("DSA", "signature"), "PSK": (None, None),
    "AES128": ("AES-128", "block-cipher"), "AES256": ("AES-256", "block-cipher"), "AES": ("AES", "block-cipher"),
    "CHACHA20": ("ChaCha20", "ae"), "POLY1305": (None, None), "3DES": ("3DES", "block-cipher"),
    "DES": ("DES", "block-cipher"), "CBC3": ("3DES", "block-cipher"), "RC4": ("RC4", "stream-cipher"),
    # suite "...-SHA" is the HMAC-SHA1 record MAC (still sound), not a bare SHA-1 hash
    "MD5": ("MD5", "hash"), "SHA": ("HMAC", "mac"), "SHA1": ("HMAC", "mac"), "SHA256": ("SHA-256", "hash"),
    "SHA384": ("SHA-384", "hash"), "SHA512": ("SHA-512", "hash"), "NULL": (None, None), "GCM": (None, None),
    "CCM": (None, None), "EXPORT": (None, None), "ANON": (None, None), "CAMELLIA128": (None, None),
    "CAMELLIA256": (None, None), "MLKEM768": ("ML-KEM-768", "kem"), "X25519MLKEM768": ("X25519MLKEM768", "combiner"),
}


def suite_algorithms(suite: str) -> list[tuple[str, str, str | None]]:
    """'ECDHE-RSA-AES256-GCM-SHA384' -> [(ECDH, key-agree, None), (RSA, pke, None), (AES-256, block-cipher, GCM), (SHA-384, hash, None)]"""
    s = suite.upper().replace("TLS_", "").replace("WITH_", "").replace("_", "-")
    toks = [t for t in s.split("-") if t]
    # "AES-256-GCM" (TLS 1.3 / IANA names) -> "AES256"
    merged = []
    for t in toks:
        if merged and merged[-1] in ("AES", "CAMELLIA", "ARIA") and t in ("128", "192", "256"):
            merged[-1] = merged[-1] + t
        else:
            merged.append(t)
    toks = merged
    out = []
    mode = "GCM" if "GCM" in toks else ("CCM" if "CCM" in toks else ("CBC" if "CBC" in toks or "CBC3" in toks else None))
    seen = set()
    for t in toks:
        alg, prim = SUITE_TOKENS.get(t, (None, None))
        if alg and alg not in seen:
            seen.add(alg)
            out.append((alg, prim, mode if prim in ("block-cipher", "ae") else None))
    if not toks[:1] or (toks and toks[0] in {"AES128", "AES256", "CHACHA20"}):
        # TLS 1.3 suites: no kex/auth in the name; key exchange is negotiated separately
        pass
    return out


VERSION_RE = re.compile(r"(TLSv1(?:\.[0-3])?|TLS1[._]?[0-3]|SSLv?[23]|TLSv1_[0-3]|TLS1_[0-3]_VERSION|SSL3_VERSION|TLS1_VERSION)", re.I)


ALL_TLS = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


def enabled_versions(val: str) -> list[str]:
    """Versions a config directive actually ENABLES. 'all -SSLv3 -TLSv1 -TLSv1.1' -> TLSv1.2, TLSv1.3.
    Apache/nginx/OpenSSL use '-' / '!' to disable; listing a version to switch it off is not using it."""
    enabled: set[str] = set()
    touched = False
    for tok in re.split(r"[\s,:;]+", val.strip().strip("\"'")):
        if not tok:
            continue
        neg = tok[0] in "-!"
        core = tok.lstrip("+-!")
        if core.lower() == "all":
            touched = True
            enabled = set() if neg else set(ALL_TLS)
            continue
        found = [normalise_version(v) for v in VERSION_RE.findall(core)]
        if not found:
            continue
        touched = True
        for v in found:
            if neg:
                enabled.discard(v)
            else:
                enabled.add(v)
    order = {v: i for i, v in enumerate(["SSLv2", "SSLv3"] + ALL_TLS)}
    return sorted(enabled, key=lambda v: order.get(v, 99)) if touched else []


def normalise_version(v: str) -> str:
    if re.match(r"^1[0-3]$", v):          # Go constants: VersionTLS12 -> "12"
        return "TLSv1." + v[1]
    u = v.upper().replace("_VERSION", "")
    u = u.replace("TLS1_", "TLSV1.").replace("TLSV1_", "TLSV1.").replace("TLS1.", "TLSV1.")
    if u == "TLS1":
        u = "TLSV1.0"
    if u == "TLSV1":
        u = "TLSV1.0"
    if u.startswith("SSL"):
        return "SSLv" + u[-1]
    if re.match(r"^TLSV1\.[0-3]$", u):
        return "TLSv" + u[4:]
    if re.match(r"^TLS1[0-3]$", u):
        return "TLSv1." + u[-1]
    return v


# ------------------------------------------------------------------------------------------------
# the collector
# ------------------------------------------------------------------------------------------------
class SourceCollector(Collector):
    name = "source"
    kinds = {"dir", "repo", "image"}

    def __init__(self):
        self._ext_lang: dict[str, str] = {}

    def _langs(self, kb: KnowledgeBase) -> dict:
        langs = kb.source_patterns.get("languages", {})
        if not self._ext_lang:
            for lang, spec in langs.items():
                for e in spec.get("extensions", []):
                    self._ext_lang[e.lower()] = lang
        return langs

    # -- entry ------------------------------------------------------------------------------------
    def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]:
        langs = self._langs(kb)
        cfg = kb.source_patterns.get("config", {})
        fallback = kb.source_patterns.get("fallback", {})
        fb_exts = set(fallback.get("extensions", []))
        cfg_globs = cfg.get("files", [])
        root = Path(target.path)
        findings: list[RawFinding] = []
        for path in walk_files(root):
            ext = path.suffix.lower()
            location = rel(path, root) if root.is_dir() else path.name
            if target.props.get("location_prefix"):
                location = target.props["location_prefix"] + location
            ctx = path_context(location)
            ctx["zone"] = target.zone
            if ext in self._ext_lang:
                lang = self._ext_lang[ext]
                text = read_text(path)
                if text is None:
                    continue
                try:
                    findings += self._scan_tree(text, lang, langs[lang], location, target, kb, ctx)
                except Exception as exc:  # grammar hiccup -> regex fallback keeps coverage
                    findings += self._scan_regex(text, location, target, kb, ctx, fallback, note=f"parse-fallback: {exc}")
            elif any(fnmatch.fnmatch(path.name, g) for g in cfg_globs):
                text = read_text(path)
                if text is not None:
                    findings += self._scan_config(text, location, target, kb, ctx, cfg)
            elif ext in fb_exts:
                text = read_text(path)
                if text is not None:
                    findings += self._scan_regex(text, location, target, kb, ctx, fallback)
        return self._absorb_unsized(findings)

    # -- tree-sitter scan -------------------------------------------------------------------------
    def _scan_tree(self, text: str, lang: str, spec: dict, location: str, target: Target, kb: KnowledgeBase,
                   ctx: dict, ) -> list[RawFinding]:
        src = text.encode("utf-8", "replace")
        tree = _parser(lang).parse(src)
        lines = text.splitlines()
        out: list[RawFinding] = []
        patterns = spec.get("calls", [])
        imports = spec.get("imports", [])
        regexes = spec.get("regex", [])
        last_by_api: dict[str, RawFinding] = {}

        def line_of(node) -> int:
            return node.start_point[0] + 1

        def snippet(node) -> str:
            ln = node.start_point[0]
            return lines[ln].strip()[:200] if ln < len(lines) else ""

        def make(name: str | None, node, pat: dict, extra: dict, primitive: str | None = None,
                 asset_type: str = "algorithm", confidence: str = "high") -> RawFinding | None:
            if asset_type == "algorithm" and not name:
                return None
            props = {k: v for k, v in {
                "primitive": primitive or pat.get("primitive"), "function": pat.get("function"),
                "mode": extra.get("mode") or pat.get("mode"), "padding": extra.get("padding") or pat.get("padding"),
                "key_size": extra.get("key_size"), "curve": extra.get("curve") or pat.get("curve"),
                "api": pat.get("api") or pat.get("callee"), "language": lang, "hash": extra.get("hash"),
                "raw": extra.get("raw"), "versions": extra.get("versions"), "cipher_suites": extra.get("cipher_suites"),
            }.items() if v not in (None, [], "")}
            props["literal"] = extra.get("literal", True)
            return RawFinding(collector="source", asset_type=asset_type, name=name or pat.get("protocol", "?"),
                              location=location, line=line_of(node), snippet=snippet(node), confidence=confidence,
                              component=target.name, props=props, context=dict(ctx))

        def walk(node):
            t = node.type
            if t in COMMENT_TYPES:
                out.extend(self._comment_findings(_text(node, src), location, line_of(node), target, kb, ctx))
                return
            if t in CALL_TYPES[lang]:
                self._handle_call(node, src, lang, patterns, kb, make, last_by_api, out)
            if t in ("import_statement", "import_from_statement", "import_declaration", "import_spec",
                     "preproc_include") or (lang == "javascript" and t == "call_expression"):
                self._handle_import(node, src, lang, imports, location, line_of(node), target, ctx, out, kb)
            for ch in node.children:
                walk(ch)

        walk(tree.root_node)
        # non-call constructs (TLS version constants etc.)
        for rx in regexes:
            for m in re.finditer(rx["pattern"], text):
                ln = text.count("\n", 0, m.start()) + 1
                if rx.get("protocol"):
                    ver = normalise_version(m.group(rx.get("version_group", 0)))
                    out.append(RawFinding("source", "protocol", rx["protocol"], location, ln, lines[ln - 1].strip()[:200],
                                          "medium", target.name, {"type": rx["protocol"].lower(), "versions": [ver],
                                                                  "language": lang, "api": "constant"}, dict(ctx)))
                elif rx.get("curve_group"):
                    cname = m.group(rx["curve_group"])
                    canon = kb.canonicalise(cname) or ("ECDH" if "P" in cname else None)
                    if canon:
                        out.append(RawFinding("source", "algorithm", canon, location, ln, lines[ln - 1].strip()[:200],
                                              "medium", target.name, {"curve": cname, "language": lang, "api": "constant",
                                                                      "primitive": "key-agree"}, dict(ctx)))
        return out

    def _handle_call(self, node, src, lang, patterns, kb, make, last_by_api, out):
        fn = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        callee = None
        if lang == "java":
            obj = node.child_by_field_name("object")
            nm = node.child_by_field_name("name")
            if node.type == "object_creation_expression":
                tp = node.child_by_field_name("type")
                callee = "new " + _text(tp, src) if tp else None
            elif nm is not None:
                callee = (_text(obj, src) + "." if obj is not None else "") + _text(nm, src)
        elif fn is not None:
            callee = _text(fn, src)
        if not callee:
            return
        callee = re.sub(r"\s+", "", callee)
        callee_bare = re.sub(r"\(.*\)$", "", callee)
        args = [c for c in (args_node.children if args_node is not None else []) if c.type not in PUNCT and not c.is_missing]
        pos_args = [a for a in args if a.type not in ("keyword_argument",)]
        for pat in patterns:
            pc = pat["callee"]
            if not (callee_bare == pc or callee_bare.endswith("." + pc) or (lang == "java" and callee_bare.endswith(pc))):
                continue
            extra: dict = {}
            # positional int key size
            kpos = pat.get("key_size_pos")
            if kpos is not None and kpos < len(pos_args) and pos_args[kpos].type in INT_TYPES:
                try:
                    extra["key_size"] = int(_text(pos_args[kpos], src).replace("_", "").rstrip("Ll"))
                except ValueError:
                    pass
            # keyword key size / curve / string kw (python keyword_argument, js object pairs)
            kkw, ckw, skw = pat.get("key_size_kw"), pat.get("curve_kw"), pat.get("string_kw")
            for a in args:
                if a.type == "keyword_argument":
                    k = _text(a.child_by_field_name("name"), src)
                    v = a.child_by_field_name("value")
                    if k == kkw and v is not None and v.type in INT_TYPES:
                        extra["key_size"] = int(_text(v, src).replace("_", ""))
                    if k == skw and v is not None and v.type in STR_TYPES:
                        extra["kwstr"] = _strip_quotes(_text(v, src))
                if a.type == "object":  # js options object
                    for pair in a.children:
                        if pair.type == "pair":
                            k = _strip_quotes(_text(pair.child_by_field_name("key"), src))
                            v = pair.child_by_field_name("value")
                            if k == kkw and v is not None and v.type in INT_TYPES:
                                extra["key_size"] = int(_text(v, src))
                            if k == ckw and v is not None and v.type in STR_TYPES:
                                extra["curve"] = _strip_quotes(_text(v, src))
                            if k == skw and v is not None and v.type in STR_TYPES:
                                extra["kwstr"] = _strip_quotes(_text(v, src))
            # curve positional
            cpos = pat.get("curve_arg")
            if cpos is not None and cpos < len(pos_args):
                ctext = _text(pos_args[cpos], src)
                m = re.search(r"(secp\d{3}[rk]1|prime256v1|P[-_]?(256|384|521)|SECP(\d{3})R1|brainpoolP\d{3}r1|NID_[A-Za-z0-9_]+|x25519|curve25519)", ctext, re.I)
                if m:
                    cv = m.group(1)
                    mm = re.match(r"P[-_]?(\d{3})", cv, re.I)
                    if mm:
                        cv = f"secp{mm.group(1)}r1"
                    mm = re.match(r"SECP(\d{3})R1", cv, re.I)
                    if mm:
                        cv = f"secp{mm.group(1)}r1"
                    extra["curve"] = cv.lower() if not cv.startswith("NID_") else cv
                elif pos_args[cpos].type in STR_TYPES:
                    extra["curve"] = _strip_quotes(ctext)
            # string-described algorithm
            spos = pat.get("string_arg")
            sval = extra.get("kwstr")
            if spos is not None and spos < len(pos_args) and pos_args[spos].type in STR_TYPES:
                sval = _strip_quotes(_text(pos_args[spos], src))
            name = pat.get("algorithm")
            primitive = pat.get("primitive")
            asset_type = "algorithm"
            literal = True
            if pat.get("parse"):
                if spos is not None and spos < len(pos_args) and pos_args[spos].type not in STR_TYPES:
                    literal = False   # algorithm name comes from a variable/config -> more agile, lower confidence
                if sval is None:
                    if pat.get("protocol"):
                        name = pat["protocol"]; asset_type = "protocol"
                    else:
                        name = name or None
                        if name is None:
                            # unknown value from variable: record as low-confidence unknown algorithm use
                            f = make(None, node, pat, {}, primitive)
                            continue
                else:
                    kind = pat["parse"]
                    if kind == "transformation":
                        d = parse_java_transformation(sval, kb); extra.update(d); name = d.get("algorithm")
                    elif kind == "signature":
                        d = parse_java_signature(sval, kb); extra.update(d); name = d.get("algorithm"); primitive = "signature"
                    elif kind == "cipher_name":
                        d = parse_cipher_name(sval, kb); extra.update(d); name = d.get("algorithm")
                        primitive = primitive or ("ae" if d.get("mode") in ("GCM", "CCM") else "block-cipher")
                    elif kind == "protocol":
                        asset_type = "protocol"; name = "TLS"
                        extra["versions"] = [normalise_version(v) for v in VERSION_RE.findall(sval)] or [sval]
                    elif kind == "cipher_string":
                        asset_type = "protocol"; name = "TLS"
                        extra["cipher_suites"] = [s for s in re.split(r"[:, ]+", sval) if s and not s.startswith("!")]
                    elif kind == "jws":
                        d = {"raw": sval}
                        alg = sval.upper()
                        if alg.startswith("HS"): name = "HMAC"; primitive = "mac"
                        elif alg.startswith("RS") or alg.startswith("PS"): name = "RSA"; primitive = "signature"
                        elif alg.startswith("ES"): name = "ECDSA"; primitive = "signature"
                        elif alg == "EDDSA": name = "Ed25519"; primitive = "signature"
                        extra.update(d)
                    else:  # algorithm
                        name = kb.canonicalise(sval, extra.get("key_size")); extra["raw"] = sval
                        if name and sval.upper() in ("EC", "ECDSA") and extra.get("curve") is None:
                            name = "ECDSA"
            elif name and extra.get("key_size"):
                name = kb.canonicalise(name, extra["key_size"]) or name
            extra["literal"] = literal
            if pat.get("attach_to"):
                prev = last_by_api.get(pat["attach_to"])
                if prev is not None and prev.props.get("key_size") is None and extra.get("key_size"):
                    prev.props["key_size"] = extra["key_size"]
                    sized = kb.canonicalise(prev.name, extra["key_size"])
                    if sized:
                        prev.name = sized
                continue
            if asset_type == "protocol":
                f = RawFinding("source", "protocol", name, "", 0, "", "high", "", {}, {})
                f = make(name, node, pat, extra, None, asset_type="protocol")
                if f is not None:
                    f.props["type"] = name.lower()
                    out.append(f)
                continue
            if pat.get("protocol") and not name:
                f = make(pat["protocol"], node, pat, {"literal": True}, None, asset_type="protocol")
                if f is not None:
                    f.props["type"] = pat["protocol"].lower(); out.append(f)
                continue
            if name is None and pat.get("mode") and not pat.get("algorithm"):
                # mode-only helper (modes.CBC) -> attach to most recent cipher finding in this file
                prev = last_by_api.get("__cipher__")
                if prev is not None and not prev.props.get("mode"):
                    prev.props["mode"] = pat["mode"]
                continue
            conf = "high" if literal else "medium"
            f = make(name, node, pat, extra, primitive, confidence=conf)
            if f is None:
                continue
            out.append(f)
            if pat.get("api"):
                last_by_api[pat["api"]] = f
            if (f.props.get("primitive") in ("block-cipher", "stream-cipher", "ae")):
                last_by_api["__cipher__"] = f
            break

    def _handle_import(self, node, src, lang, imports, location, line, target, ctx, out, kb):
        text = _text(node, src)
        if lang == "javascript":
            m = re.search(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)", text)
            if not m and node.type != "import_statement":
                return
            mod = m.group(1) if m else (re.search(r"from\s+['\"]([^'\"]+)['\"]", text) or re.search(r"import\s+['\"]([^'\"]+)['\"]", text))
            if mod is None:
                return
            mod = mod if isinstance(mod, str) else mod.group(1)
        elif lang == "c":
            m = re.search(r"#include\s*[<\"]([^>\"]+)[>\"]", text)
            if not m:
                return
            mod = m.group(1)
        else:
            mod = re.sub(r"^(import|from)\s+", "", text.split("\n")[0]).split(" ")[0].strip("\"'; ()")
        for imp in imports:
            if mod == imp["module"] or mod.startswith(imp["module"]):
                out.append(RawFinding("source", "library", imp["library"], location, line, text.strip()[:200], "high",
                                      target.name, {"module": mod, "language": lang, "import": True}, dict(ctx)))
                return

    def _comment_findings(self, comment: str, location: str, line: int, target: Target, kb: KnowledgeBase, ctx: dict):
        out = []
        for m in re.finditer(r"\b(RSA|ECDSA|ECDH|AES-?\d{3}|3DES|DES|MD5|SHA-?1|SHA-?256|RC4|Blowfish|Kyber|Dilithium|ML-KEM|ML-DSA)\b", comment, re.I):
            canon = kb.canonicalise(m.group(1))
            if canon:
                c = dict(ctx); c["in_comment"] = True
                out.append(RawFinding("source", "algorithm", canon, location, line, comment.strip()[:200], "low",
                                      target.name, {"api": "comment"}, c))
        return out

    # -- config directives ------------------------------------------------------------------------
    def _scan_config(self, text: str, location: str, target: Target, kb: KnowledgeBase, ctx: dict, cfg: dict):
        out: list[RawFinding] = []
        directives = {d["key"].lower(): d for d in cfg.get("directives", [])}
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(("#", ";", "//")):
                continue
            m = re.match(r"^([A-Za-z_.\-]+)\s*[=:]?\s*(.+?)\s*;?$", line)
            if not m:
                continue
            key, val = m.group(1).lower(), m.group(2).strip().strip("\"'")
            d = directives.get(key)
            if not d:
                continue
            props: dict = {"directive": m.group(1), "raw": val, "api": "config"}
            parse = d.get("parse")
            if d.get("protocol"):
                props["type"] = d["protocol"].lower()
                if parse == "versions":
                    props["versions"] = enabled_versions(val) or [val]
                elif parse == "cipher_string":
                    suites = [s for s in re.split(r"[:, ]+", val) if s and not s.startswith(("!", "-"))]
                    props["cipher_suites"] = suites
                    for s in suites:
                        for alg, prim, mode in suite_algorithms(s):
                            out.append(RawFinding("source", "algorithm", alg, location, i, line[:200], "high", target.name,
                                                  {"primitive": prim, "mode": mode, "api": "config", "suite": s,
                                                   "directive": m.group(1)}, dict(ctx)))
                elif parse == "curves":
                    props["curves"] = [c for c in re.split(r"[:, ]+", val) if c]
                    for c in props["curves"]:
                        canon = kb.canonicalise(c) or ("ECDH" if kb.curve(c) else None)
                        if canon:
                            out.append(RawFinding("source", "algorithm", canon, location, i, line[:200], "high", target.name,
                                                  {"primitive": "key-agree", "curve": c, "api": "config", "directive": m.group(1)}, dict(ctx)))
                elif parse == "ssh_list":
                    props["algorithms"] = [c for c in re.split(r"[:, ]+", val) if c]
                    for c in props["algorithms"]:
                        canon = kb.canonicalise(c.split("@")[0])
                        if canon:
                            out.append(RawFinding("source", "algorithm", canon, location, i, line[:200], "high", target.name,
                                                  {"api": "config", "directive": m.group(1), "raw": c}, dict(ctx)))
                elif parse == "ipsec_proposal":
                    props["proposals"] = [p for p in re.split(r"[, ]+", val) if p]
                    for p in props["proposals"]:
                        for tok in p.split("-"):
                            canon = kb.canonicalise(tok)
                            if canon:
                                out.append(RawFinding("source", "algorithm", canon, location, i, line[:200], "medium", target.name,
                                                      {"api": "config", "directive": m.group(1), "raw": p}, dict(ctx)))
                elif parse == "openssl_conf_command":
                    mm = re.match(r"(\w+)\s+(.+)", val)
                    if mm:
                        props["command"] = mm.group(1); props["raw"] = mm.group(2)
                        if mm.group(1).lower() in ("groups", "curves"):
                            props["curves"] = mm.group(2).split(":")
                        elif mm.group(1).lower() in ("ciphersuites", "cipherstring"):
                            props["cipher_suites"] = mm.group(2).split(":")
                        elif mm.group(1).lower() in ("minprotocol", "maxprotocol"):
                            props["versions"] = [normalise_version(mm.group(2))]
                out.append(RawFinding("source", "protocol", d["protocol"], location, i, line[:200], "high", target.name,
                                      props, dict(ctx)))
            elif d.get("hardware"):
                out.append(RawFinding("source", "related-crypto-material", d["hardware"], location, i, line[:200], "medium",
                                      target.name, {"type": "hardware-module", "api": "config", "raw": val}, dict(ctx)))
            elif d.get("cloud"):
                out.append(RawFinding("source", "related-crypto-material", d["cloud"], location, i, line[:200], "medium",
                                      target.name, {"type": "cloud-service", "api": "config", "raw": val}, dict(ctx)))
        return out

    # -- regex fallback ----------------------------------------------------------------------------
    def _scan_regex(self, text: str, location: str, target: Target, kb: KnowledgeBase, ctx: dict, fallback: dict,
                    note: str | None = None):
        words = fallback.get("words", [])
        if not words:
            return []
        rx = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True)) + r")(?![A-Za-z0-9])", re.I)
        out = []
        seen = set()
        for i, line in enumerate(text.splitlines(), 1):
            for m in rx.finditer(line):
                canon = kb.canonicalise(m.group(1))
                if not canon or (canon, i) in seen:
                    continue
                seen.add((canon, i))
                c = dict(ctx)
                if note:
                    c["note"] = note
                c["regex_fallback"] = True
                out.append(RawFinding("source", "algorithm", canon, location, i, line.strip()[:200], "low", target.name,
                                      {"api": "regex", "raw": m.group(1)}, c))
        return out

    # -- post-processing --------------------------------------------------------------------------
    @staticmethod
    def _absorb_unsized(findings: list[RawFinding]) -> list[RawFinding]:
        """An unsized 'AES' in a file that also has 'AES-256' is the same asset: fold it in as extra evidence."""
        sized = {}
        for f in findings:
            if f.asset_type == "algorithm" and f.name.startswith("AES-"):
                sized.setdefault((f.component, f.location), f)
        out = []
        for f in findings:
            if f.asset_type == "algorithm" and f.name == "AES" and (f.component, f.location) in sized:
                s = sized[(f.component, f.location)]
                if not s.props.get("mode") and f.props.get("mode"):
                    s.props["mode"] = f.props["mode"]
                s.context.setdefault("extra_lines", []).append(f.line)
                continue
            out.append(f)
        return out
