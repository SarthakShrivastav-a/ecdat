from pathlib import Path

from ecdat.collectors.base import Target
from ecdat.collectors.source import SourceCollector, suite_algorithms, parse_java_signature, parse_cipher_name
from ecdat.knowledge import KnowledgeBase

ZOO = Path(__file__).parent / "fixtures" / "zoo" / "src"
kb = KnowledgeBase()


def _names(findings):
    return {(f.name, f.props.get("key_size")) for f in findings if f.asset_type == "algorithm"}


def _collect(sub, zone="internal"):
    return SourceCollector().collect(Target(kind="dir", path=str(ZOO / sub), name=sub, zone=zone), kb)


def test_python_finds_rsa_ecdsa_aes_sha256():
    fs = _collect("python")
    names = _names(fs)
    assert ("RSA", 2048) in names
    assert ("ECDSA", None) in names
    assert ("AES-256", 256) in names
    assert ("SHA-256", None) in names
    ecdsa = [f for f in fs if f.name == "ECDSA" and f.props.get("curve")][0]
    assert ecdsa.props["curve"] == "secp256r1"
    assert any(f.asset_type == "library" and f.name == "pyca-cryptography" for f in fs)


def test_python_context_flags():
    fs = _collect("python")
    md5 = [f for f in fs if f.name == "MD5" and not f.context.get("in_comment")][0]
    assert md5.context["is_test"] is False and md5.location.endswith("utils/cache.py")
    sha1 = [f for f in fs if f.name == "SHA-1" and not f.context.get("in_comment")][0]
    assert sha1.context["is_test"] is True


def test_java_transformation_parsing():
    fs = _collect("java")
    aes = [f for f in fs if f.name == "AES"][0]
    assert aes.props["mode"] == "CBC" and aes.props["padding"] == "PKCS5Padding"
    names = _names(fs)
    assert ("RSA", 2048) in names          # KeyPairGenerator + initialize(2048) attached
    assert ("3DES", None) in names
    assert ("MD5", None) in names
    ecdsa = [f for f in fs if f.name == "ECDSA"][0]
    assert ecdsa.props["hash"] == "SHA-256" and ecdsa.props["primitive"] == "signature"


def test_go_js_c():
    go = _collect("go")
    assert ("RSA", 4096) in _names(go)
    assert any(f.asset_type == "protocol" and "TLSv1.2" in f.props.get("versions", []) for f in go)
    js = _names(_collect("js", "external"))
    assert ("MD5", None) in js and ("AES-256", 256) in js and ("RSA", 2048) in js and ("RSA", 1024) in js
    c = _collect("c")
    cn = _names(c)
    assert ("RSA", 2048) in cn and ("AES-128", 128) in cn and ("MD5", None) in cn and ("SHA-1", None) in cn
    assert any(f.asset_type == "library" and f.name == "openssl" for f in c)


def test_nginx_protocol_finding():
    fs = _collect("nginx", "external")
    tls = [f for f in fs if f.asset_type == "protocol" and f.props.get("versions")]
    assert any("TLSv1.2" in f.props["versions"] and "TLSv1.3" in f.props["versions"] for f in tls)
    suites = [f for f in fs if f.asset_type == "protocol" and f.props.get("cipher_suites")][0]
    assert "ECDHE-RSA-AES256-GCM-SHA384" in suites.props["cipher_suites"]
    names = _names(fs)
    assert ("ECDH", None) in names and ("AES-256", None) in names and ("ChaCha20", None) in names
    curve = [f for f in fs if f.props.get("curve") == "prime256v1"]
    assert curve, "ssl_ecdh_curve should yield an ECDH finding"


def test_helpers():
    algs = suite_algorithms("ECDHE-RSA-AES256-GCM-SHA384")
    assert ("ECDH", "key-agree", None) in algs and ("AES-256", "block-cipher", "GCM") in algs
    assert parse_java_signature("SHA256withECDSA", kb)["hash"] == "SHA-256"
    d = parse_cipher_name("aes-128-cbc", kb)
    assert d["algorithm"] == "AES-128" and d["mode"] == "CBC"


def test_config_versions_respect_negation():
    from ecdat.collectors.source import enabled_versions
    assert enabled_versions("all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1") == ["TLSv1.2", "TLSv1.3"]
    assert enabled_versions("TLSv1 TLSv1.1 TLSv1.2") == ["TLSv1.0", "TLSv1.1", "TLSv1.2"]
    assert enabled_versions("TLSv1.2 TLSv1.3;") == ["TLSv1.2", "TLSv1.3"]
    assert enabled_versions("-ALL +TLSv1.3") == ["TLSv1.3"]


def test_cipher_suite_sha_is_hmac_not_bare_sha1():
    from ecdat.collectors.source import suite_algorithms
    names = [a for a, _, _ in suite_algorithms("ECDHE-RSA-AES128-SHA")]
    assert "HMAC" in names and "SHA-1" not in names
