#!/usr/bin/env python3
"""Builds the password-mode golden files from FORMAT.md, independently of the Swift code.

It uses the reference Argon2 implementation (argon2-cffi) and pyca/cryptography for
HKDF-SHA256 and AES-256-GCM, so a Swift test that opens these files checks the whole
format against a second implementation, not against itself.

    python3 -m venv venv && venv/bin/pip install argon2-cffi==23.1.0 cryptography==43.0.3
    venv/bin/python make_password_vectors.py

Every value is fixed, so the output is byte-for-byte reproducible.
"""
import hashlib
import struct
import unicodedata
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PASSWORD = "correct horse battery staple"
OPS, MEM = 3, 256 << 20  # the cheapest cost v1 accepts, so the test stays fast
ARGON2_SALT = bytes(range(0x00, 0x10))
HKDF_SALT = bytes(range(0x20, 0x40))
BASE_NONCE = bytes(range(0x40, 0x4C))
CHUNK = 65536


def hkdf(ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=HKDF_SALT, info=info).derive(ikm)


def build(plaintext: bytes, filename: str | None) -> bytes:
    password = unicodedata.normalize("NFC", PASSWORD).encode("utf-8")
    ikm = hash_secret_raw(password, ARGON2_SALT, time_cost=OPS, memory_cost=MEM // 1024,
                          parallelism=1, hash_len=32, type=Type.ID, version=0x13)
    file_key = hkdf(ikm, b"Chotam v1 file key")
    commitment = hkdf(ikm, b"Chotam v1 key commitment")

    header = (b"CHOTAM" + struct.pack(">HBI", 1, 1, 125)
              + struct.pack(">I", CHUNK) + HKDF_SALT + BASE_NONCE + commitment
              + ARGON2_SALT + struct.pack(">QQ", OPS, MEM))
    assert len(header) == 125
    header_hash = hashlib.sha256(header).digest()

    name = filename.encode("utf-8") if filename else b""
    stream = struct.pack(">H", len(name)) + name + plaintext
    chunks = [stream[i:i + CHUNK] for i in range(0, len(stream), CHUNK)] or [b""]

    aes = AESGCM(file_key)
    body = b""
    for index, chunk in enumerate(chunks):
        final = index == len(chunks) - 1
        nonce = BASE_NONCE[:4] + bytes(a ^ b for a, b in zip(BASE_NONCE[4:], struct.pack(">Q", index)))
        aad = header_hash + struct.pack(">QB", index, 1 if final else 0)
        body += aes.encrypt(nonce, chunk, aad)
    return header + body


def pattern(count: int) -> bytes:
    return bytes(i % 251 for i in range(count))


here = Path(__file__).parent
small = build(b"Chotam golden vector: password mode.\n", "vector.txt")
# 2 + 65634 = 65636 stream bytes: one full chunk, then a 100-byte final chunk.
two_chunks = build(pattern(65634), None)
(here / "password-small.enc").write_bytes(small)
(here / "password-two-chunks.enc").write_bytes(two_chunks)
for name, data in [("password-small.enc", small), ("password-two-chunks.enc", two_chunks)]:
    print(name, len(data), hashlib.sha256(data).hexdigest())
