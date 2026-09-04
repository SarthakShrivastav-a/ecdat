from pathlib import Path

from ecdat.collectors.base import Target
from ecdat.collectors.dependency import DependencyCollector
from ecdat.knowledge import KnowledgeBase

ZOO = Path(__file__).parent / "fixtures" / "zoo" / "src"
kb = KnowledgeBase()


def _collect(sub):
    t = Target("dir", str(ZOO / sub), sub, "internal", props={"use_syft": False})
    return DependencyCollector().collect(t, kb)


def test_requirements():
    fs = _collect("python")
    names = {f.name for f in fs}
    assert {"cryptography", "pycryptodome", "pyjwt"} <= names
    c = [f for f in fs if f.name == "cryptography"][0]
    assert c.props["version"] == "42.0.5" and "RSA" in c.props["provides"] and c.props["ecosystem"] == "pypi"


def test_package_json():
    fs = _collect("js")
    names = {f.name for f in fs}
    assert {"node-forge", "jsonwebtoken", "crypto-js", "bcrypt"} <= names
    assert [f for f in fs if f.name == "jsonwebtoken"][0].props["wrapper"] is True


def test_go_mod_runtime_and_xcrypto():
    fs = _collect("go")
    rt = [f for f in fs if f.name == "runtime:go"][0]
    assert rt.props["runtime"] == {"go": "1.22"} and rt.props["pqc_native_from"] == "1.24"
    xc = [f for f in fs if f.name == "golang.org/x/crypto"][0]
    assert "ChaCha20" in xc.props["provides"]


def test_pom():
    fs = _collect("java")
    bc = [f for f in fs if f.name == "org.bouncycastle:bcprov-jdk18on"][0]
    assert bc.props["version"] == "1.78" and "ML-KEM-768" in bc.props["provides"] and bc.props["pqc_native_from"] == "1.79"
    rt = [f for f in fs if f.name == "runtime:java"][0]
    assert rt.props["runtime"] == {"java": "17"}
