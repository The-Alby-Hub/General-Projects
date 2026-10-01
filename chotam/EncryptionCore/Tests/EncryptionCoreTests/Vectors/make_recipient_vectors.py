#!/usr/bin/env python3
"""Builds the recipient-mode golden files from FORMAT.md §2, §4–§6, independently of the Swift code.

Nothing here comes from CryptoKit, swift-crypto or libsodium:

- Identities are derived exactly as in make_identity_vectors.py (whose helpers are
  reused): Argon2id from argon2-cffi, HKDF from pyca/cryptography, X-Wing key generation
  from the draft, ML-KEM-768 from kyber-py, ML-DSA-65 from dilithium-py, Ed25519 from
  pyca/cryptography. The golden Alice derived here must equal identity-v1.pqid byte for
  byte, or the script aborts.
- X-Wing encapsulation and decapsulation follow draft-connolly-cfrg-xwing-kem-06 §5
  (EncapsulateDerand, Decapsulate, combiner SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\\.//^\\")),
  with ML-KEM-768 from kyber-py. They are checked against the draft's three published test
  vectors, and OpenSSL's ML-KEM-768 (via pyca/cryptography) must decapsulate every
  ML-KEM ciphertext made here to the same shared secret.
- HPKE (RFC 9180) base mode is written out here from the RFC: LabeledExtract,
  LabeledExpand, the key schedule and single-shot Seal, with suite_id
  "HPKE" ‖ 0x647A ‖ 0x0001 ‖ 0x0002. Only the KEM is X-Wing; the key schedule and AEAD are
  checked against RFC 9180's official test vector for the same KDF and AEAD (base mode,
  DHKEM(X25519), HKDF-SHA256, AES-256-GCM).
- AES-256-GCM chunks, the header, the wrap context and the signed message are written out
  from the spec text. Both signature halves are verified with a second implementation
  (OpenSSL's ML-DSA-65 and Ed25519).
- Every file is then decrypted again here, through the reader's steps (find my stanza,
  verify, unwrap, check the commitment, open every chunk), before it is written.

    python3 -m venv venv
    venv/bin/pip install kyber-py==1.2.0 dilithium-py==1.4.0 cryptography==50.0.2 argon2-cffi==23.1.0
    venv/bin/python make_recipient_vectors.py

Every input is fixed (Data Keys, salts, nonces, X-Wing encapsulation seeds), and both
signatures are deterministic, so the output is byte-for-byte reproducible.
"""
import hashlib
import hmac
import struct
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

from make_identity_vectors import canonical_passphrase, crockford, grouped, hkdf, raw_public

HERE = Path(__file__).parent
CHUNK = 65536
OPS, MEM = 3, 256 << 20

# Alice is the Phase 5a golden identity (FORMAT.md §9.7). Bob is a second one, derived
# the same way: seven distinct EFF words (lines 200, 1300, 2400, 3500, 4600, 5700, 6800).
ALICE = dict(passphrase="agreement curve flakily ligament pretty shrimp unbundle",
             salt=bytes(range(0xA0, 0xB0)), name="Alice", file="identity-v1.pqid")
BOB = dict(passphrase="angrily copy excretion joyride perish scouting tipped",
           salt=bytes(range(0xB0, 0xC0)), name="Bob", file="identity-bob-v1.pqid")

XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")  # "\.//^\"
HPKE_SUITE = b"HPKE" + struct.pack(">HHH", 0x647A, 0x0001, 0x0002)
SIGNATURE_LABEL = b"Chotam v1 signature"
WRAP_CONTEXT_LABEL = b"Chotam v1 wrap context"

# draft-connolly-cfrg-xwing-kem test vectors (spec/test-vectors.json):
# seed, eseed → shared secret, SHA-256 of the 1120-byte ciphertext.
XWING_ENCAPS_REFERENCE = [
    ("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
     "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"
     "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
     "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384",
     "17cd532d657e44c897ca6583e548a5424fc70bf54f99515a4d2bcf99e3469f33"),
    ("badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
     "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef"
     "aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
     "f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150",
     "1661ea86d608a1924ba30840cb0a65f13ae051e3aec9cf0f064efc0bc92f2154"),
    ("ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
     "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619"
     "f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
     "953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f",
     "d3ca5578500344b5896cffc4fd740c9311946b82951df155e6fd86a7966b43c6"),
]

# RFC 9180 test vector: mode_base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
# (cfrg/draft-irtf-cfrg-hpke test-vectors.json). Only the key schedule and AEAD are used.
RFC9180_SUITE = b"HPKE" + struct.pack(">HHH", 0x0020, 0x0001, 0x0002)
RFC9180 = dict(
    shared_secret="3101c54c3a4f87439eaac080699ed9bbcc726ffe44e860c0424ccb7e3e2ead7b",
    info="4f6465206f6e2061204772656369616e2055726e",
    key="f50b0609186798729ed0564b36ef2ef8044f1f9d05636874d1f46c819c7a669f",
    base_nonce="151d9929e2449747889bc923",
    aad0="436f756e742d30",
    pt="4265617574792069732074727574682c20747275746820626561757479",
    ct0="e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
)


# MARK: Identities

def derive_identity(spec: dict) -> dict:
    """FORMAT.md §9.6, as in make_identity_vectors.py (no key file)."""
    salt = spec["salt"]
    master = hash_secret_raw(canonical_passphrase(spec["passphrase"]), salt, time_cost=OPS,
                             memory_cost=MEM // 1024, parallelism=1, hash_len=32, type=Type.ID, version=0x13)
    xwing_seed = hkdf(master, salt, b"Chotam v1 identity X-Wing seed")
    mldsa_seed = hkdf(master, salt, b"Chotam v1 identity ML-DSA-65 seed")
    ed_seed = hkdf(master, salt, b"Chotam v1 identity Ed25519 seed")

    xwing = xwing_expand(xwing_seed)
    mldsa_pk, mldsa_sk = ML_DSA_65.key_derive(mldsa_seed)
    assert raw_public(mldsa.MLDSA65PrivateKey.from_seed_bytes(mldsa_seed).public_key()) == mldsa_pk
    ed_sk = ed25519.Ed25519PrivateKey.from_private_bytes(ed_seed)
    ed_pk = raw_public(ed_sk.public_key())

    name = spec["name"].encode()
    body = (b"CHOTAMID" + struct.pack(">H", 1)
            + struct.pack(">H", 1216) + xwing["pk"]
            + struct.pack(">H", 1952) + mldsa_pk
            + struct.pack(">H", 32) + ed_pk
            + struct.pack(">BBQQB", 1, 0, OPS, MEM, 1) + salt
            + struct.pack(">B", len(name)) + name + struct.pack(">H", 0))
    message = b"Chotam v1 identity signature" + body
    signature = ed_sk.sign(message) + ML_DSA_65.sign(mldsa_sk, message, deterministic=True)
    pqid = body + struct.pack(">H", len(signature)) + signature

    return dict(
        name=spec["name"], xwing=xwing, mldsa_pk=mldsa_pk, mldsa_sk=mldsa_sk, ed_sk=ed_sk, ed_pk=ed_pk,
        pqid=pqid,
        encryption_key_id=hashlib.sha256(b"Chotam v1 encryption key id" + xwing["pk"]).digest(),
        signing_key_id=hashlib.sha256(b"Chotam v1 signing key id" + mldsa_pk + ed_pk).digest(),
        fingerprint=grouped(crockford(hashlib.sha256(
            b"Chotam v1 identity fingerprint" + xwing["pk"] + mldsa_pk + ed_pk).digest()[:20])),
    )


# MARK: X-Wing (draft-connolly-cfrg-xwing-kem-06 §5)

def xwing_expand(seed: bytes) -> dict:
    """expandDecapsulationKey: SHAKE256(seed, 96) → ML-KEM (d ‖ z) and the X25519 secret."""
    expanded = hashlib.shake_256(seed).digest(96)
    pk_m, sk_m = ML_KEM_768._keygen_internal(expanded[0:32], expanded[32:64])
    sk_x = expanded[64:96]
    pk_x = raw_public(x25519.X25519PrivateKey.from_private_bytes(sk_x).public_key())
    return dict(seed=seed, d_z=expanded[0:64], sk_m=sk_m, sk_x=sk_x, pk=pk_m + pk_x)


def x25519_shared(secret: bytes, public: bytes) -> bytes:
    return x25519.X25519PrivateKey.from_private_bytes(secret).exchange(
        x25519.X25519PublicKey.from_public_bytes(public))


def xwing_combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def xwing_encapsulate(pk: bytes, eseed: bytes) -> tuple[bytes, bytes]:
    """EncapsulateDerand(pk, eseed) → (ss, ct)."""
    assert len(pk) == 1216 and len(eseed) == 64
    pk_m, pk_x = pk[:1184], pk[1184:]
    ek_x = eseed[32:64]
    ct_x = raw_public(x25519.X25519PrivateKey.from_private_bytes(ek_x).public_key())
    ss_x = x25519_shared(ek_x, pk_x)
    ss_m, ct_m = ML_KEM_768._encaps_internal(pk_m, eseed[0:32])
    return xwing_combiner(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def xwing_decapsulate(ct: bytes, key: dict) -> bytes:
    assert len(ct) == 1120
    ct_m, ct_x = ct[:1088], ct[1088:]
    ss_m = ML_KEM_768._decaps_internal(key["sk_m"], ct_m)
    # Second implementation: OpenSSL's ML-KEM-768, from the same (d ‖ z) seed.
    assert mlkem.MLKEM768PrivateKey.from_seed_bytes(key["d_z"]).decapsulate(ct_m) == ss_m
    ss_x = x25519_shared(key["sk_x"], ct_x)
    return xwing_combiner(ss_m, ss_x, ct_x, key["pk"][1184:])


# MARK: HPKE (RFC 9180), base mode, single shot

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt or bytes(32), b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = struct.pack(">H", length) + b"HPKE-v1" + suite + label + info
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac_sha256(prk, block + labeled_info + bytes([counter]))
        out += block
        counter += 1
    return out[:length]


def key_schedule(suite: bytes, shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    """KeySchedule(mode_base, shared_secret, info, psk = "", psk_id = "") → (key, base_nonce)."""
    psk_id_hash = labeled_extract(suite, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(suite, b"", b"info_hash", info)
    context = bytes([0x00]) + psk_id_hash + info_hash
    secret = labeled_extract(suite, shared_secret, b"secret", b"")
    return (labeled_expand(suite, secret, b"key", context, 32),
            labeled_expand(suite, secret, b"base_nonce", context, 12))


def hpke_seal(pk: bytes, eseed: bytes, info: bytes, aad: bytes, pt: bytes) -> tuple[bytes, bytes]:
    shared_secret, enc = xwing_encapsulate(pk, eseed)
    key, nonce = key_schedule(HPKE_SUITE, shared_secret, info)
    return enc, AESGCM(key).encrypt(nonce, pt, aad)  # sequence number 0: nonce = base_nonce


def hpke_open(key_pair: dict, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:
    key, nonce = key_schedule(HPKE_SUITE, xwing_decapsulate(enc, key_pair), info)
    return AESGCM(key).decrypt(nonce, ct, aad)


# MARK: The .enc file

def chunk_nonce(base: bytes, index: int) -> bytes:
    return base[:4] + bytes(a ^ b for a, b in zip(base[4:], struct.pack(">Q", index)))


def build(sender: dict, recipients: list[dict], data_key: bytes, hkdf_salt: bytes, base_nonce: bytes,
          eseed_tag: bytes, plaintext: bytes, filename: str | None) -> bytes:
    commitment = hkdf(data_key, hkdf_salt, b"Chotam v1 key commitment")
    file_key = hkdf(data_key, hkdf_salt, b"Chotam v1 file key")

    # FORMAT.md §6.2: contacts' stanzas sorted by key ID, the sender's own stanza last.
    contacts = sorted((r for r in recipients if r is not sender), key=lambda r: r["encryption_key_id"])
    ordered = contacts + [sender]
    count = len(ordered)
    header_length = 126 + 1204 * count

    prelude = b"CHOTAM" + struct.pack(">HBI", 1, 2, header_length)
    common = struct.pack(">I", CHUNK) + hkdf_salt + base_nonce + commitment
    sender_part = sender["signing_key_id"] + struct.pack(">B", count)
    wrap_context = hashlib.sha256(WRAP_CONTEXT_LABEL + prelude + common + sender_part
                                  + b"".join(r["encryption_key_id"] for r in ordered)).digest()

    stanzas = b""
    for index, recipient in enumerate(ordered):
        eseed = hashlib.sha512(b"Chotam golden eseed " + eseed_tag + bytes([index])).digest()
        key_id = recipient["encryption_key_id"]
        enc, wrapped = hpke_seal(recipient["xwing"]["pk"], eseed, wrap_context, key_id, data_key)
        assert (len(enc), len(wrapped)) == (1120, 48)
        stanzas += key_id + struct.pack(">H", 1120) + enc + struct.pack(">H", 48) + wrapped

    header = prelude + common + sender_part + stanzas
    assert len(header) == header_length
    header_hash = hashlib.sha256(header).digest()

    name = filename.encode() if filename else b""
    stream = struct.pack(">H", len(name)) + name + plaintext
    chunks = [stream[i:i + CHUNK] for i in range(0, len(stream), CHUNK)]
    aes = AESGCM(file_key)
    body = b""
    for index, chunk in enumerate(chunks):
        final = index == len(chunks) - 1
        aad = header_hash + struct.pack(">QB", index, 1 if final else 0)
        body += aes.encrypt(chunk_nonce(base_nonce, index), chunk, aad)

    message = (SIGNATURE_LABEL + header_hash + hashlib.sha256(body).digest()
               + struct.pack(">Q", len(chunks)))
    ed_sig = sender["ed_sk"].sign(message)
    ml_sig = ML_DSA_65.sign(sender["mldsa_sk"], message, deterministic=True)
    assert (len(ed_sig), len(ml_sig)) == (64, 3309)
    return header + body + ed_sig + ml_sig


def read(data: bytes, me: dict, known_senders: list[dict]) -> tuple[bytes, str | None, str]:
    """Opens a file the way FORMAT.md §7 says a reader must, as a self-check."""
    version, mode, header_length = struct.unpack(">HBI", data[6:13])
    assert data[:6] == b"CHOTAM" and (version, mode) == (1, 2)
    header, rest = data[:header_length], data[header_length:]
    body, trailer = rest[:-3373], rest[-3373:]
    count = header[125]
    assert header_length == 126 + 1204 * count
    stanzas = [header[126 + 1204 * i: 126 + 1204 * (i + 1)] for i in range(count)]
    mine = [s for s in stanzas if s[:32] == me["encryption_key_id"]]
    assert len(mine) == 1, "not for me"
    sender = [s for s in known_senders if s["signing_key_id"] == header[93:125]]
    assert len(sender) == 1, "unknown sender"
    sender = sender[0]

    # Pass 1: the signature, with no secret.
    header_hash = hashlib.sha256(header).digest()
    # FORMAT.md §5.4: while more than a sealed chunk remains, the next one is non-final.
    sizes, remaining = [], len(body)
    while remaining > CHUNK + 16:
        sizes.append(CHUNK + 16)
        remaining -= CHUNK + 16
    assert remaining >= 16
    sizes.append(remaining)
    message = (SIGNATURE_LABEL + header_hash + hashlib.sha256(body).digest() + struct.pack(">Q", len(sizes)))
    ed25519.Ed25519PublicKey.from_public_bytes(sender["ed_pk"]).verify(trailer[:64], message)
    mldsa.MLDSA65PublicKey.from_public_bytes(sender["mldsa_pk"]).verify(trailer[64:], message)
    assert ML_DSA_65.verify(sender["mldsa_pk"], message, trailer[64:])

    # Unwrap, check the commitment, then decrypt.
    wrap_context = hashlib.sha256(WRAP_CONTEXT_LABEL + header[:126]
                                  + b"".join(s[:32] for s in stanzas)).digest()
    stanza = mine[0]
    data_key = hpke_open(me["xwing"], stanza[34:1154], wrap_context, stanza[:32], stanza[1156:1204])
    hkdf_salt, base_nonce, commitment = header[17:49], header[49:61], header[61:93]
    assert hmac.compare_digest(hkdf(data_key, hkdf_salt, b"Chotam v1 key commitment"), commitment)
    aes = AESGCM(hkdf(data_key, hkdf_salt, b"Chotam v1 file key"))
    stream, offset = b"", 0
    for index, size in enumerate(sizes):
        final = index == len(sizes) - 1
        aad = header_hash + struct.pack(">QB", index, 1 if final else 0)
        stream += aes.decrypt(chunk_nonce(base_nonce, index), body[offset:offset + size], aad)
        offset += size
    name_length = struct.unpack(">H", stream[:2])[0]
    name = stream[2:2 + name_length].decode() if name_length else None
    return stream[2 + name_length:], name, sender["name"]


def pattern(count: int) -> bytes:
    return bytes(i % 251 for i in range(count))


def self_tests() -> None:
    for seed, eseed, ss, ct_digest in XWING_ENCAPS_REFERENCE:
        key = xwing_expand(bytes.fromhex(seed))
        shared, ct = xwing_encapsulate(key["pk"], bytes.fromhex(eseed))
        assert shared.hex() == ss and hashlib.sha256(ct).hexdigest() == ct_digest, "X-Wing encaps vector"
        assert xwing_decapsulate(ct, key) == shared, "X-Wing decaps vector"

    v = {k: bytes.fromhex(x) for k, x in RFC9180.items()}
    key, nonce = key_schedule(RFC9180_SUITE, v["shared_secret"], v["info"])
    assert (key, nonce) == (v["key"], v["base_nonce"]), "RFC 9180 key schedule"
    assert AESGCM(key).encrypt(nonce, v["pt"], v["aad0"]) == v["ct0"], "RFC 9180 seal"


def main() -> None:
    self_tests()
    alice, bob = derive_identity(ALICE), derive_identity(BOB)
    assert alice["pqid"] == (HERE / ALICE["file"]).read_bytes(), "Alice must be the Phase 5a golden identity"
    (HERE / BOB["file"]).write_bytes(bob["pqid"])

    files = {
        # Alice → Bob (and herself), signed by Alice: one chunk, with a filename.
        "recipients-from-alice.enc": (
            build(alice, [bob, alice], data_key=bytes(range(0xC0, 0xE0)), hkdf_salt=bytes(range(0x60, 0x80)),
                  base_nonce=bytes(range(0x80, 0x8C)), eseed_tag=b"alice",
                  plaintext=b"Chotam golden vector: recipient mode.\n", filename="vector.txt"),
            b"Chotam golden vector: recipient mode.\n", "vector.txt"),
        # Bob → Alice (and himself), signed by Bob: a full chunk, then a 100-byte final chunk.
        "recipients-from-bob.enc": (
            build(bob, [alice, bob], data_key=bytes(range(0xE0, 0x100)), hkdf_salt=bytes(range(0x30, 0x50)),
                  base_nonce=bytes(range(0x50, 0x5C)), eseed_tag=b"bob",
                  plaintext=pattern(65634), filename=None),
            pattern(65634), None),
    }
    for name, (data, plaintext, filename) in files.items():
        for reader in (alice, bob):
            assert read(data, reader, [alice, bob]) == (plaintext, filename, name.split("-")[-1][:-4].capitalize())
        (HERE / name).write_bytes(data)

    for who in (alice, bob):
        print(f"== {who['name']} ==")
        print(f"encryption key ID    {who['encryption_key_id'].hex()}")
        print(f"signing key ID       {who['signing_key_id'].hex()}")
        print(f"fingerprint          {who['fingerprint']}")
        print(f"X-Wing seed          {who['xwing']['seed'].hex()}")
        print(f".pqid                {len(who['pqid'])} bytes, SHA-256 {hashlib.sha256(who['pqid']).hexdigest()}")
    for name, (data, _, _) in files.items():
        print(f"{name:<26} {len(data)} bytes, SHA-256 {hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
