"""Dependency collector: manifests and lock files -> crypto libraries (CycloneDX `provides` edges) + runtime versions.
Syft (optional) adds packages the manifests miss."""
from __future__ import annotations

import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from ecdat import tools
from ecdat.collectors.base import Collector, Target, path_context, rel, walk_files
from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding

MANIFESTS = {
    "requirements.txt": "pypi", "requirements-dev.txt": "pypi", "pyproject.toml": "pypi", "Pipfile": "pypi",
    "setup.py": "pypi", "package.json": "npm", "package-lock.json": "npm", "go.mod": "go", "pom.xml": "maven",
    "build.gradle": "maven", "build.gradle.kts": "maven", "Cargo.toml": "cargo", "Gemfile": "rubygems",
    "composer.json": "composer",
}


def _lib_finding(target: Target, eco: str, name: str, version: str | None, location: str, line: int, snippet: str,
                 kb: KnowledgeBase, confidence: str = "high", runtime: dict | None = None) -> RawFinding | None:
    sig = (kb.libraries.get(eco) or {}).get(name)
    if sig is None:
        return None
    props = {"ecosystem": eco, "version": version, "provides": list(sig.get("provides", [])),
             "pqc_native": bool(sig.get("pqc_native")), "pqc_native_from": sig.get("pqc_native_from"),
             "wrapper": bool(sig.get("wrapper")), "cloud": bool(sig.get("cloud")), "hardware": bool(sig.get("hardware")),
             "stdlib": bool(sig.get("stdlib")), "api": "manifest"}
    if runtime:
        props["runtime"] = runtime
    ctx = path_context(location)
    ctx["zone"] = target.zone
    return RawFinding("dependency", "library", name, location, line, snippet[:200], confidence, target.name, props, ctx)


def _runtime_finding(target: Target, runtime: str, version: str, location: str, line: int, kb: KnowledgeBase) -> RawFinding:
    info = (kb.libraries.get("runtimes") or {}).get(runtime, {})
    ctx = path_context(location)
    ctx["zone"] = target.zone
    return RawFinding("dependency", "library", f"runtime:{runtime}", location, line, f"{runtime} {version}", "high",
                      target.name, {"ecosystem": "runtime", "runtime": {runtime: version}, "version": version,
                                    "pqc_native_from": info.get("pqc_native_from"), "pqc_native": bool(info.get("pqc_native")),
                                    "note": info.get("note"), "api": "manifest", "provides": []}, ctx)


class DependencyCollector(Collector):
    name = "dependency"
    kinds = {"dir", "repo", "image"}

    def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]:
        root = Path(target.path)
        out: list[RawFinding] = []
        seen: set[tuple] = set()
        for path in walk_files(root):
            eco = MANIFESTS.get(path.name)
            if not eco:
                continue
            location = rel(path, root) if root.is_dir() else path.name
            if target.props.get("location_prefix"):
                location = target.props["location_prefix"] + location
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            parser = getattr(self, f"_parse_{path.name.replace('.', '_').replace('-', '_')}", None) or getattr(self, f"_parse_{eco}")
            for name, version, line, snippet, runtime in parser(text):
                if runtime:
                    for rt, ver in runtime.items():
                        if ("runtime", rt) not in seen:
                            seen.add(("runtime", rt))
                            out.append(_runtime_finding(target, rt, ver, location, line, kb))
                    if name is None:
                        continue
                f = _lib_finding(target, eco, name, version, location, line, snippet, kb)
                if f and (eco, name) not in seen:
                    seen.add((eco, name))
                    out.append(f)
        if target.props.get("use_syft", True) and tools.find("syft") and root.is_dir():
            out += self._syft(target, root, kb, seen)
        return out

    # ---- parsers: yield (name, version, line, snippet, runtime_dict_or_None) ---------------------
    def _parse_pypi(self, text):
        for i, line in enumerate(text.splitlines(), 1):
            s = line.split("#")[0].strip()
            if not s or s.startswith(("-", "git+", "http")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(?:[=<>!~]+\s*([^,;\s]+))?", s)
            if m:
                yield m.group(1).split("[")[0].lower().replace("_", "-"), m.group(2), i, s, None

    _parse_requirements_txt = _parse_pypi
    _parse_requirements_dev_txt = _parse_pypi

    def _parse_pyproject_toml(self, text):
        in_deps = False
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith("requires-python"):
                m = re.search(r"([\d.]+)", s)
                if m:
                    yield None, None, i, s, {"python": m.group(1)}
            if s.startswith("dependencies") or s.startswith("[tool.poetry.dependencies]") or s.startswith("[project.optional-dependencies"):
                in_deps = True
                continue
            if in_deps and s.startswith("[") and "dependencies" not in s:
                in_deps = False
            if in_deps:
                for m in re.finditer(r"[\"']([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([=<>!~]+\s*[^\"',;\s]+)?[\"']", s):
                    yield m.group(1).lower().replace("_", "-"), (m.group(2) or "").lstrip("=<>!~ ") or None, i, s, None
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*=\s*[\"'^~]*([\d.]+)", s)
                if m and not s.startswith("["):
                    yield m.group(1).lower(), m.group(2), i, s, None

    def _parse_Pipfile(self, text):
        return self._parse_pyproject_toml(text)

    def _parse_setup_py(self, text):
        for i, line in enumerate(text.splitlines(), 1):
            for m in re.finditer(r"[\"']([A-Za-z0-9_.\-]+)\s*([=<>!~]+\s*[\d.]+)?[\"']", line):
                if "install_requires" in text:
                    yield m.group(1).lower().replace("_", "-"), (m.group(2) or "").lstrip("=<>!~ ") or None, i, line.strip(), None

    def _parse_npm(self, text):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        engines = data.get("engines", {}) if isinstance(data, dict) else {}
        if engines.get("node"):
            yield None, None, 1, f"engines.node {engines['node']}", {"node": re.sub(r"[^\d.]", "", engines["node"].split(" ")[0])}
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, ver in (data.get(section) or {}).items():
                yield name, str(ver).lstrip("^~>=<"), 1, f'"{name}": "{ver}"', None
        for pkg_path, meta in (data.get("packages") or {}).items():  # package-lock v2/v3
            if not pkg_path:
                continue
            name = pkg_path.split("node_modules/")[-1]
            yield name, (meta or {}).get("version"), 1, pkg_path, None

    _parse_package_json = _parse_npm
    _parse_package_lock_json = _parse_npm

    def _parse_go(self, text):
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            m = re.match(r"^go\s+(\d+\.\d+(?:\.\d+)?)", s)
            if m:
                yield None, None, i, s, {"go": m.group(1)}
                continue
            m = re.match(r"^(?:require\s+)?([A-Za-z0-9._\-/]+\.[A-Za-z]+/[A-Za-z0-9._\-/]+)\s+v?([\w.\-+]+)", s)
            if m and not s.startswith("module"):
                name = m.group(1)
                yield name, m.group(2), i, s, None
                # match on prefix too (golang.org/x/crypto/ssh -> golang.org/x/crypto)
                parts = name.split("/")
                for n in range(3, len(parts)):
                    yield "/".join(parts[:n]), m.group(2), i, s, None

    _parse_go_mod = _parse_go

    def _parse_maven(self, text):
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        props = {p.tag.replace(ns, ""): (p.text or "").strip() for p in root.iter(f"{ns}properties") for p in p}
        jv = props.get("maven.compiler.source") or props.get("java.version") or props.get("maven.compiler.release") or props.get("maven.compiler.target")
        if jv:
            yield None, None, 1, f"java {jv}", {"java": jv.replace("1.", "") if jv.startswith("1.") else jv}
        for dep in root.iter(f"{ns}dependency"):
            g = dep.findtext(f"{ns}groupId") or ""
            a = dep.findtext(f"{ns}artifactId") or ""
            v = dep.findtext(f"{ns}version") or None
            if v and v.startswith("${"):
                v = props.get(v[2:-1], v)
            yield f"{g}:{a}", v, 1, f"{g}:{a}:{v}", None

    _parse_pom_xml = _parse_maven

    def _parse_build_gradle(self, text):
        for i, line in enumerate(text.splitlines(), 1):
            m = re.search(r"[\"']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)[\"']", line)
            if m:
                yield f"{m.group(1)}:{m.group(2)}", m.group(3), i, line.strip(), None
            m = re.search(r"(?:sourceCompatibility|languageVersion|JavaVersion\.VERSION_)[\s=(]*[\"']?(?:1\.)?(\d{1,2})", line)
            if m:
                yield None, None, i, line.strip(), {"java": m.group(1)}

    _parse_build_gradle_kts = _parse_build_gradle

    def _parse_cargo(self, text):
        in_deps = False
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith("["):
                in_deps = "dependencies" in s
                continue
            if in_deps:
                m = re.match(r"^([A-Za-z0-9_\-]+)\s*=\s*(?:\"([^\"]+)\"|\{[^}]*version\s*=\s*\"([^\"]+)\")", s)
                if m:
                    yield m.group(1), m.group(2) or m.group(3), i, s, None

    _parse_Cargo_toml = _parse_cargo

    def _parse_rubygems(self, text):
        for i, line in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*gem\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?", line)
            if m:
                yield m.group(1), m.group(2), i, line.strip(), None

    _parse_Gemfile = _parse_rubygems

    def _parse_composer(self, text):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        for section in ("require", "require-dev"):
            for name, ver in (data.get(section) or {}).items():
                if name == "php":
                    yield None, None, 1, f"php {ver}", {"php": re.sub(r"[^\d.]", "", str(ver))}
                else:
                    yield name, str(ver), 1, f'"{name}": "{ver}"', None

    _parse_composer_json = _parse_composer

    # ---- syft (optional) ------------------------------------------------------------------------
    def _syft(self, target: Target, root: Path, kb: KnowledgeBase, seen: set) -> list[RawFinding]:
        exe = tools.find("syft")
        try:
            proc = subprocess.run([str(exe), f"dir:{root}", "-o", "cyclonedx-json", "-q"], capture_output=True,
                                  text=True, timeout=600, encoding="utf-8", errors="replace")
            data = json.loads(proc.stdout[proc.stdout.find("{"):])
        except Exception:
            return []
        eco_map = {"python": "pypi", "npm": "npm", "go-module": "go", "java-archive": "maven", "rust-crate": "cargo",
                   "gem": "rubygems", "php-composer": "composer", "apk": "system", "deb": "system", "rpm": "system"}
        out = []
        for c in data.get("components", []):
            purl = c.get("purl", "")
            m = re.match(r"pkg:([a-z\-]+)/(.+?)(?:@([^?#]+))?(?:[?#].*)?$", purl)
            if not m:
                continue
            ptype, name, ver = m.group(1), m.group(2), m.group(3)
            eco = {"pypi": "pypi", "npm": "npm", "golang": "go", "maven": "maven", "cargo": "cargo", "gem": "rubygems",
                   "composer": "composer", "apk": "system", "deb": "system", "rpm": "system"}.get(ptype)
            if not eco:
                continue
            if eco == "maven":
                name = name.replace("/", ":")
            if eco == "npm":
                name = name.replace("%40", "@")
            if eco == "system":
                name = name.split("/")[-1].replace("libssl", "openssl").replace("libcrypto", "openssl")
                name = re.sub(r"\d.*$", "", name) if name.startswith("openssl") else name
            if (eco, name) in seen:
                continue
            f = _lib_finding(target, eco, name, ver, f"syft:{purl}", 0, purl, kb, confidence="medium")
            if f:
                f.props["api"] = "syft"
                seen.add((eco, name))
                out.append(f)
        return out
