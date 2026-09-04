"""Payment service auth - planted crypto zoo.
truth: RSA-2048 keygen, RSA-OAEP encrypt, ECDSA P-256 sign, AES-256-GCM seal, SHA-256 digest (all hardcoded)
"""
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def make_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def encrypt_card(pubkey, pan: bytes) -> bytes:
    return pubkey.encrypt(pan, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


def sign_receipt(data: bytes) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def seal(record: bytes) -> bytes:
    key = AESGCM.generate_key(bit_length=256)
    return AESGCM(key).encrypt(os.urandom(12), record, None)


def export_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
