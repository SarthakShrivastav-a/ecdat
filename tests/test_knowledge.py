from ecdat.knowledge import KnowledgeBase

kb = KnowledgeBase()


def test_canonicalise_aliases():
    assert kb.canonicalise("rsaEncryption") == "RSA"
    assert kb.canonicalise("sha256WithRSAEncryption") == "RSA"
    assert kb.canonicalise("aes", 256) == "AES-256"
    assert kb.canonicalise("aes-256-gcm") == "AES-256"
    assert kb.canonicalise("AES/CBC/PKCS5Padding") == "AES"
    assert kb.canonicalise("md5") == "MD5"
    assert kb.canonicalise("DESede/CBC/PKCS5Padding") == "3DES"
    assert kb.canonicalise("X25519MLKEM768") == "X25519MLKEM768"
    assert kb.canonicalise("nonsense-xyz") is None


def test_info_has_quantum_class():
    assert kb.info("RSA")["quantum"] == "broken"
    assert kb.info("AES-256")["quantum"] == "safe"
    assert kb.info("MD5")["quantum"] == "legacy-broken"
    assert kb.info("AES-128")["quantum"] == "weakened"


def test_registry_families_loaded():
    assert "RSASSA-PKCS1" in kb.registry_families and "ML-KEM" in kb.registry_families
    for canon, info in kb.algorithms.items():
        fam = info.get("family")
        if fam not in {"TLS", "SSH", "IPsec", "FN-DSA", "HQC"}:
            assert fam in kb.registry_families, f"{canon} family {fam} not in CycloneDX registry"


def test_security_bits_and_curves():
    assert kb.security_bits("RSA", 2048) == 112 and kb.security_bits("RSA", 3000) == 112
    assert kb.security_bits("AES-256", None) == 256
    assert kb.curve("prime256v1")["oid"] == "1.2.840.10045.3.1.7"
