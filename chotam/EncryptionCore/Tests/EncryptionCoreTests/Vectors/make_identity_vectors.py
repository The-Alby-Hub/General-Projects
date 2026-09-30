#!/usr/bin/env python3
"""Builds the identity golden values from FORMAT.md §6.1 and §9, independently of the Swift code.

Nothing here comes from CryptoKit or swift-crypto:

- X-Wing key generation follows draft-connolly-cfrg-xwing-kem (SHAKE256 seed expansion,
  ML-KEM-768 KeyGen_internal, X25519), with ML-KEM-768 from kyber-py. It is checked
  against the draft's own test vectors before anything is written.
- ML-DSA-65 key generation and signing come from dilithium-py.
- pyca/cryptography (OpenSSL) is a second, unrelated implementation of both ML-KEM-768
  and ML-DSA-65. The script aborts unless it derives the same public keys and accepts
  the signature.
- Key IDs, the fingerprint, Crockford base32 and the .pqid layout are written out here
  from the spec text.

    python3 -m venv venv
    venv/bin/pip install kyber-py==1.2.0 dilithium-py==1.4.0 cryptography==50.0.2
    venv/bin/python make_identity_vectors.py

Every input is fixed and the signature is ML-DSA's deterministic variant, so the output
is byte-for-byte reproducible. (Chotam itself signs with CryptoKit's default, which may
be hedged; any valid signature verifies.)
"""
import hashlib
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519
from cryptography.hazmat.primitives import serialization
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

XWING_SEED = bytes(range(0x60, 0x80))  # 32-byte X-Wing decapsulation-key seed
MLDSA_SEED = bytes(range(0x80, 0xA0))  # 32-byte ML-DSA-65 seed (xi)
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


def raw_public(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


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


def main() -> None:
    for seed, digest in XWING_REFERENCE.items():
        assert hashlib.sha256(xwing_public_key(bytes.fromhex(seed))).hexdigest() == digest

    xwing_pk = xwing_public_key(XWING_SEED)
    mldsa_pk, mldsa_sk = ML_DSA_65.key_derive(MLDSA_SEED)
    assert raw_public(mldsa.MLDSA65PrivateKey.from_seed_bytes(MLDSA_SEED).public_key()) == mldsa_pk
    assert (len(xwing_pk), len(mldsa_pk)) == (1216, 1952)

    enc_id = hashlib.sha256(b"Chotam v1 encryption key id" + xwing_pk).digest()
    sig_id = hashlib.sha256(b"Chotam v1 signing key id" + mldsa_pk).digest()
    fp_digest = hashlib.sha256(b"Chotam v1 identity fingerprint" + xwing_pk + mldsa_pk).digest()
    fingerprint = crockford(fp_digest[:20])

    name = NAME.encode("utf-8")
    body = (b"CHOTAMID" + struct.pack(">H", 1)
            + struct.pack(">H", len(xwing_pk)) + xwing_pk
            + struct.pack(">H", len(mldsa_pk)) + mldsa_pk
            + struct.pack(">B", len(name)) + name)
    message = b"Chotam v1 identity signature" + body
    signature = ML_DSA_65.sign(mldsa_sk, message, deterministic=True)
    assert len(signature) == 3309
    assert ML_DSA_65.verify(mldsa_pk, message, signature)
    mldsa.MLDSA65PublicKey.from_public_bytes(mldsa_pk).verify(signature, message)  # raises if invalid
    pqid = body + struct.pack(">H", len(signature)) + signature

    out = Path(__file__).with_name("identity-v1.pqid")
    out.write_bytes(pqid)

    print(f"xwing seed          {XWING_SEED.hex()}")
    print(f"mldsa seed          {MLDSA_SEED.hex()}")
    print(f"SHA-256(xwing pk)   {hashlib.sha256(xwing_pk).hexdigest()}")
    print(f"SHA-256(mldsa pk)   {hashlib.sha256(mldsa_pk).hexdigest()}")
    print(f"encryption key ID   {enc_id.hex()}")
    print(f"signing key ID      {sig_id.hex()}")
    print(f"fingerprint digest  {fp_digest[:20].hex()}")
    print(f"fingerprint         {grouped(fingerprint)}")
    print(f"{out.name}   {len(pqid)} bytes, SHA-256 {hashlib.sha256(pqid).hexdigest()}")
    # Crockford spot checks used by the Swift tests.
    print(f"crockford 00*20     {crockford(bytes(20))}")
    print(f"crockford ff*20     {crockford(bytes([0xFF]) * 20)}")
    print(f"crockford 00..13    {crockford(bytes(range(20)))}")


if __name__ == "__main__":
    main()
