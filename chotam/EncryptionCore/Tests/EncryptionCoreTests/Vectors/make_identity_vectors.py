#!/usr/bin/env python3
"""Builds the identity golden files from FORMAT.md §6.1 and §9, independently of the Swift code.

A Chotam identity is derived from a passphrase (FORMAT.md §9.6): Argon2id, then HKDF-SHA256
into three key seeds. Nothing here comes from CryptoKit, swift-crypto or libsodium:

- Argon2id is the reference implementation (argon2-cffi).
- HKDF-SHA256 comes from pyca/cryptography, and is checked against a hand-written RFC 5869
  HKDF (hashlib + hmac).
- X-Wing key generation follows draft-connolly-cfrg-xwing-kem (SHAKE256 seed expansion,
  ML-KEM-768 KeyGen_internal, X25519), with ML-KEM-768 from kyber-py. It is checked
  against the draft's own test vectors before anything is written.
- ML-DSA-65 key generation and signing come from dilithium-py.
- pyca/cryptography (OpenSSL) is a second, unrelated implementation of both ML-KEM-768
  and ML-DSA-65. The script aborts unless it derives the same public keys and accepts
  the signature. It also provides Ed25519 (RFC 8032, deterministic).
- Key IDs, the fingerprint, Crockford base32 and the .pqid layout are written out here
  from the spec text.

    python3 -m venv venv
    venv/bin/pip install kyber-py==1.2.0 dilithium-py==1.4.0 cryptography==50.0.2 argon2-cffi==23.1.0
    venv/bin/python make_identity_vectors.py

Every input is fixed, and both signatures are deterministic (Ed25519 always is; ML-DSA
uses its deterministic variant), so the output is byte-for-byte reproducible. (Chotam
itself may sign with hedged randomness; any valid signature verifies.)
"""
import hashlib
import hmac
import struct
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

# Inputs. Seven distinct words from the EFF large wordlist (lines 100, 1500, 2600, 3700,
# 4830, 5900, 7000), typed with odd spacing and case to exercise canonicalisation.
TYPED_PASSPHRASE = "  Agreement curve\tflakily  LIGAMENT pretty shrimp unbundle "
KDF_SALT = bytes(range(0xA0, 0xB0))       # 16 bytes
OPS, MEM = 3, 256 << 20                   # the cheapest cost an identity may declare (tests stay fast)
KEY_FILE = bytes(range(256)) * 4          # 1 KiB, for the key-file vector
NAME = "Alice"

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# draft-connolly-cfrg-xwing-kem test vectors: seed → SHA-256 of the 1216-byte public key.
XWING_REFERENCE = {
    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26":
        "2e816deebcd76c5c80d0cd2d174478871658e8e2ff42bc9d4a6e486372e856bb",
    "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea":
        "c42ba5f8430d7d2c83739338203819f090e8303ce9c8b02107c272bfa5376916",
    "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9":
        "6b080d6b84f095342092fa7a22423e58bd681397ad0ef00eac92bd254db4fa95",
}

ED25519_SIG, MLDSA_SIG = 64, 3309


def raw_public(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def canonical_passphrase(typed: str) -> bytes:
    """FORMAT.md §9.6: lowercase words joined by single spaces (the words are ASCII)."""
    return " ".join(typed.lower().split()).encode("ascii")


def hkdf_by_hand(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    out = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)
    assert out == hkdf_by_hand(ikm, salt, info)
    return out


def xwing_public_key(seed: bytes) -> bytes:
    expanded = hashlib.shake_256(seed).digest(96)
    d, z, sk_x = expanded[0:32], expanded[32:64], expanded[64:96]
    pk_m, _ = ML_KEM_768._keygen_internal(d, z)
    # Second implementation: OpenSSL's ML-KEM-768 from the same (d ‖ z) seed.
    assert raw_public(mlkem.MLKEM768PrivateKey.from_seed_bytes(d + z).public_key()) == pk_m
    pk_x = raw_public(x25519.X25519PrivateKey.from_private_bytes(sk_x).public_key())
    return pk_m + pk_x


def crockford(data: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    assert len(bits) % 5 == 0
    return "".join(CROCKFORD[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def grouped(text: str) -> str:
    return " ".join(text[i:i + 4] for i in range(0, len(text), 4))


def build(key_file: bytes | None, out_name: str) -> None:
    passphrase = canonical_passphrase(TYPED_PASSPHRASE)
    master = hash_secret_raw(passphrase, KDF_SALT, time_cost=OPS, memory_cost=MEM // 1024,
                             parallelism=1, hash_len=32, type=Type.ID, version=0x13)
    ikm = master
    if key_file is not None:
        ikm += hashlib.sha256(b"Chotam v1 key file" + key_file).digest()
    xwing_seed = hkdf(ikm, KDF_SALT, b"Chotam v1 identity X-Wing seed")
    mldsa_seed = hkdf(ikm, KDF_SALT, b"Chotam v1 identity ML-DSA-65 seed")
    ed_seed = hkdf(ikm, KDF_SALT, b"Chotam v1 identity Ed25519 seed")
    contacts_key = hkdf(ikm, KDF_SALT, b"Chotam v1 contacts key")
    assert len({xwing_seed, mldsa_seed, ed_seed, contacts_key}) == 4

    xwing_pk = xwing_public_key(xwing_seed)
    mldsa_pk, mldsa_sk = ML_DSA_65.key_derive(mldsa_seed)
    assert raw_public(mldsa.MLDSA65PrivateKey.from_seed_bytes(mldsa_seed).public_key()) == mldsa_pk
    ed_sk = ed25519.Ed25519PrivateKey.from_private_bytes(ed_seed)
    ed_pk = raw_public(ed_sk.public_key())
    assert (len(xwing_pk), len(mldsa_pk), len(ed_pk)) == (1216, 1952, 32)

    enc_id = hashlib.sha256(b"Chotam v1 encryption key id" + xwing_pk).digest()
    sig_id = hashlib.sha256(b"Chotam v1 signing key id" + mldsa_pk + ed_pk).digest()
    fp_digest = hashlib.sha256(b"Chotam v1 identity fingerprint" + xwing_pk + mldsa_pk + ed_pk).digest()
    fingerprint = crockford(fp_digest[:20])

    name = NAME.encode("utf-8")
    flags = 1 if key_file is not None else 0
    body = (b"CHOTAMID" + struct.pack(">H", 1)
            + struct.pack(">H", len(xwing_pk)) + xwing_pk
            + struct.pack(">H", len(mldsa_pk)) + mldsa_pk
            + struct.pack(">H", len(ed_pk)) + ed_pk
            + struct.pack(">BBQQB", 1, flags, OPS, MEM, 1) + KDF_SALT
            + struct.pack(">B", len(name)) + name
            + struct.pack(">H", 0))  # no extensions
    message = b"Chotam v1 identity signature" + body
    ed_sig = ed_sk.sign(message)
    ml_sig = ML_DSA_65.sign(mldsa_sk, message, deterministic=True)
    assert (len(ed_sig), len(ml_sig)) == (ED25519_SIG, MLDSA_SIG)
    assert ML_DSA_65.verify(mldsa_pk, message, ml_sig)
    mldsa.MLDSA65PublicKey.from_public_bytes(mldsa_pk).verify(ml_sig, message)  # raises if invalid
    ed25519.Ed25519PublicKey.from_public_bytes(ed_pk).verify(ed_sig, message)  # raises if invalid
    signature = ed_sig + ml_sig
    pqid = body + struct.pack(">H", len(signature)) + signature

    out = Path(__file__).with_name(out_name)
    out.write_bytes(pqid)

    print(f"== {out_name} ==")
    print(f"canonical passphrase {passphrase.decode()}")
    print(f"key file             {'SHA-256 ' + hashlib.sha256(key_file).hexdigest() if key_file else 'none'}")
    print(f"master (Argon2id)    {master.hex()}")
    print(f"X-Wing seed          {xwing_seed.hex()}")
    print(f"ML-DSA-65 seed       {mldsa_seed.hex()}")
    print(f"Ed25519 seed         {ed_seed.hex()}")
    print(f"contacts key         {contacts_key.hex()}")
    print(f"SHA-256(xwing pk)    {hashlib.sha256(xwing_pk).hexdigest()}")
    print(f"SHA-256(mldsa pk)    {hashlib.sha256(mldsa_pk).hexdigest()}")
    print(f"Ed25519 pk           {ed_pk.hex()}")
    print(f"encryption key ID    {enc_id.hex()}")
    print(f"signing key ID       {sig_id.hex()}")
    print(f"fingerprint digest   {fp_digest[:20].hex()}")
    print(f"fingerprint          {grouped(fingerprint)}")
    print(f"file                 {len(pqid)} bytes, SHA-256 {hashlib.sha256(pqid).hexdigest()}")


def main() -> None:
    for seed, digest in XWING_REFERENCE.items():
        assert hashlib.sha256(xwing_public_key(bytes.fromhex(seed))).hexdigest() == digest
    # RFC 5869 test case 1, for the hand-written HKDF.
    assert hkdf_by_hand(bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    build(None, "identity-v1.pqid")
    build(KEY_FILE, "identity-keyfile-v1.pqid")
    # Crockford spot checks used by the Swift tests.
    print(f"crockford 00*20      {crockford(bytes(20))}")
    print(f"crockford ff*20      {crockford(bytes([0xFF]) * 20)}")
    print(f"crockford 00..13     {crockford(bytes(range(20)))}")


if __name__ == "__main__":
    main()
