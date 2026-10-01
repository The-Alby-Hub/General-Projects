# Chotam file format, version 1

This document specifies every byte of a `.enc` file produced by Chotam (חוֹתָם, Hebrew for "seal").
All integers are **unsigned big-endian**. `‖` means concatenation.
`SHA-256` and `HKDF-SHA256` are as in FIPS 180-4 and RFC 5869.

Status of each part in the implementation:

| Part | Specified here | Implemented |
|---|---|---|
| Header prelude, common fields, parser limits | yes | Phase 1 |
| Chunked AES-256-GCM body, key schedule, key commitment | yes | Phase 1 |
| Encrypted metadata record (filename) | yes | Phase 1 |
| Password-mode parameters (Argon2id) | yes | fields parsed in Phase 1, KDF in Phase 2 |
| Golden test files (password mode) | §8 | Phase 2 |
| Recipient-mode stanzas (HPKE X-Wing) | yes | fields parsed in Phase 1, HPKE in Phase 5b |
| Trailer (hybrid Ed25519 + ML-DSA-65 signature) | yes | framing in Phase 1, signing in Phase 5b |
| Two-pass decryption, signer lookup (§6.3, §7) | yes | Phase 5b |
| Golden test files (recipient mode) | §8 | Phase 5b |
| Key IDs (§6.1) | yes | Phase 4; signing key ID over both signing keys in Phase 5a |
| Public identity file `.pqid` and fingerprints (§9) | yes | Phase 4, reworked in Phase 5a (three keys, KDF block, extensions, hybrid self-signature) |
| Passphrase-derived identity (§9.6) | yes | Phase 5a |
| Files Chotam keeps on the Mac: the public identity and the encrypted contacts file (§10) | yes | Phase 5a (replaces Phase 4's Keychain records) |

Every key, ciphertext and signature size here comes from the relevant standard and is
**confirmed against the macOS 26 SDK** by `IdentityKeyTests` (passed on macOS,
2026-09-30): X-Wing public key 1216, encapsulated key 1120, HPKE-wrapped Data Key 48,
ML-DSA-65 public key 1952, signature 3309. Ed25519 (public key 32, signature 64) is
checked by the same tests from Phase 5a on. The format is not frozen until Phase 7.

---

## 1. Overall layout

```
+----------------------+  header (plaintext, authenticated)
| prelude     13 bytes |
| common      80 bytes |
| mode params variable |
+----------------------+
| chunk 0              |  body: AES-256-GCM chunks
| chunk 1              |
| ...                  |
| chunk n-1 (final)    |
+----------------------+
| trailer              |  recipient mode only: hybrid signature (3373 bytes)
+----------------------+
```

There are **no length fields for the body or the trailer**. The trailer has a fixed size
for its mode, and chunk boundaries follow from the fixed chunk size (§5.4), so an
attacker cannot lie about either.

## 2. Header

### 2.1 Prelude (13 bytes)

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 6 | magic | ASCII `CHOTAM` (`43 48 4F 54 41 4D`) |
| 6 | 2 | version | must be `1` |
| 8 | 1 | mode | `1` = password, `2` = recipients; anything else is rejected |
| 9 | 4 | headerLength | total header size **including** the prelude (see §2.4) |

A reader validates the prelude **before reading anything else**. It only then reads
`headerLength − 13` more bytes, so a hostile length can never trigger a large allocation.

### 2.2 Common fields (80 bytes)

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 13 | 4 | chunkSize | must be `65536` in v1 |
| 17 | 32 | hkdfSalt | random per file |
| 49 | 12 | baseNonce | random per file |
| 61 | 32 | commitment | key-commitment tag (§4.2) |

### 2.3 Mode parameters

**Password mode (`mode = 1`), 32 bytes, offset 93:**

| Size | Field | Rule |
|---:|---|---|
| 16 | argon2Salt | random per file |
| 8 | opsLimit | accepted range `3…8` |
| 8 | memLimit | bytes; accepted range `256 MiB … 1 GiB` |

Encryption always writes libsodium's `OPSLIMIT_SENSITIVE` (4) and
`MEMLIMIT_SENSITIVE` (1 GiB). Decryption rejects values outside the ranges above
**before** running Argon2id, so a crafted file cannot force a huge memory or CPU cost.

**Recipient mode (`mode = 2`), offset 93:**

| Size | Field | Rule |
|---:|---|---|
| 32 | senderKeyID | signing-key ID of the sender (§6.1, both signing keys) |
| 1 | recipientCount | `1…64` |
| 1204 × count | stanzas | see below |

Each stanza:

| Size | Field | Rule |
|---:|---|---|
| 32 | keyID | recipient's encryption-key ID (§6.1); no duplicates within a header |
| 2 | encLength | must equal `1120`, the X-Wing encapsulated-key size |
| 1120 | encapsulatedKey | HPKE `enc` |
| 2 | wrappedLength | must equal `48` (32-byte Data Key + 16-byte GCM tag) |
| 48 | wrappedDataKey | HPKE ciphertext of the Data Key |

The length fields are redundant in v1 but kept so a later version can change the
KEM without redesigning the framing. v1 rejects any other value.

### 2.4 Header length rules

| Mode | headerLength |
|---|---|
| password | exactly `125` |
| recipients | exactly `126 + 1204 × recipientCount` (so `1330 … 77182`) |

The reader also enforces a hard ceiling of 128 KiB. A header whose `headerLength`
doesn't match its contents exactly, or that has bytes left over after the last field,
is rejected.

### 2.5 Header hash

`headerHash = SHA-256(rawHeaderBytes)`. It is computed over the **exact bytes read
from the file**, never over a re-encoding. It is bound into every chunk (§5.3) and into
the signature (§6.3), so changing any header byte breaks decryption.

## 3. Plaintext stream and metadata record

The encrypted stream carries a small metadata record followed by the file contents:

```
plaintextStream = nameLength (UInt16) ‖ name (nameLength bytes, UTF-8) ‖ fileBytes
```

- `nameLength = 0` means no filename was stored.
- The name must be valid UTF-8 and at most 1024 bytes. It must not be `.` or `..`, and must
  not contain `/`, C0 or C1 control characters, or Unicode bidirectional controls
  (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069). The last rule stops a name such as
  `invoice` + U+202E + `fdp.exe` from displaying as `invoiceexe.pdf`.
- The record always fits inside chunk 0: it is at most 1026 bytes and a chunk holds 65536.

The filename is therefore **encrypted and authenticated**. It isn't visible in the
header. It is still chosen by the file's author, so a reader must treat it as untrusted
text. How Chotam uses it when saving a decrypted file is in SECURITY.md D12.

## 4. Key schedule

### 4.1 Input keying material (IKM)

The IKM is always exactly 32 bytes:

- **Password mode:** `IKM = Argon2id(password, argon2Salt, opsLimit, memLimit, outLen = 32)`.
  The password is normalised to Unicode NFC and encoded as UTF-8 first, so the same
  password typed on a different keyboard layout derives the same key.
  Exact parameters, as libsodium's `crypto_pwhash` with `crypto_pwhash_ALG_ARGON2ID13` uses them:
  - Argon2id, version `0x13` (RFC 9106);
  - parallelism (lanes) `1`, fixed by libsodium;
  - time cost `t = opsLimit`;
  - memory cost `m = memLimit / 1024` KiB (`memLimit` is stored in bytes);
  - no secret key and no associated data;
  - 32-byte output.

  Nothing is trimmed: leading and trailing spaces are part of the password. The format
  accepts any password, even an empty one; the strength rule (SECURITY.md D6) is applied
  by the encryptor, never by the decryptor.
- **Recipient mode:** `IKM = DataKey`, 32 random bytes generated per file.

### 4.2 Derived values

```
fileKey    = HKDF-SHA256(IKM, salt = hkdfSalt, info = "Chotam v1 file key",       L = 32)
commitment = HKDF-SHA256(IKM, salt = hkdfSalt, info = "Chotam v1 key commitment", L = 32)
```

- `hkdfSalt` is fresh for every file, so `fileKey` is unique per file even if the IKM
  repeats (the same password, for example).
- AES-GCM is not key-committing: a ciphertext can be built to decrypt validly under
  two different keys. The commitment tag stops that. It is derived from the same IKM and
  salt as `fileKey` but with a distinct `info` label, so a header commits to exactly one
  IKM, and therefore one `fileKey`, under the collision resistance of HKDF-SHA256.
- The decryptor recomputes `commitment` and compares it with the header value in
  **constant time before opening any chunk**. On mismatch, decryption stops.

## 5. Body

### 5.1 Chunking

- The plaintext stream is split into chunks of exactly `chunkSize` (65536) bytes,
  except the last.
- The last chunk (the **final** chunk) holds `0 … 65536` bytes.
- If the stream length is an exact multiple of 65536, the last full chunk is the final
  one; no empty chunk follows it.
- An empty chunk only ever appears as the single chunk of an empty stream (not possible
  in v1, since the metadata record is always at least 2 bytes). A reader rejects an
  empty final chunk at index > 0.
- The chunk count must be below 2³².

Each chunk on disk is `ciphertext ‖ tag`: the chunk's plaintext length plus 16 bytes.

### 5.2 Nonces

```
nonce(i) = baseNonce XOR (0x00000000 ‖ UInt64BE(i))
```

The chunk index is XORed into the last 8 bytes of the 12-byte base nonce. Nonces are
unique within a file because the index is. They are unique across files because
`fileKey` itself is unique per file (§4.2). The random `baseNonce` is extra defence in
depth.

### 5.3 Associated data

```
aad(i) = headerHash (32) ‖ UInt64BE(i) (8) ‖ finalFlag (1: 0x01 if final, else 0x00)
```

This binds each chunk to its file (the header hash), its position (the index) and
whether it is last (the final flag). As a result:

- **reordered or duplicated chunks** fail (wrong index);
- **truncation at a chunk boundary** fails (the new last chunk was sealed as non-final);
- **appended data** fails (the old final chunk is no longer last, or the extra bytes
  don't authenticate);
- **header edits** fail (the header hash changes).

### 5.4 Finding chunk boundaries when reading

With `S = chunkSize + 16` and `T` = the trailer size for the mode (`0` for password
mode, `3373` for recipient mode, §6.3), the reader keeps a read-ahead buffer:

- If more than `S + T` bytes remain, the next `S` bytes are a **non-final** chunk.
- Otherwise the input has ended. The remaining bytes are the **final** chunk followed by
  exactly `T` trailer bytes. The final chunk must be at least 16 bytes.

The reader never reads more than `S + T + 1` bytes at a time.

## 6. Recipient mode (Phase 5b)

### 6.1 Key IDs (implemented in Phase 4, signing key ID updated in Phase 5a)

```
encryptionKeyID = SHA-256("Chotam v1 encryption key id" ‖ X-Wing public key)
signingKeyID    = SHA-256("Chotam v1 signing key id"    ‖ ML-DSA-65 public key ‖ Ed25519 public key)
```

The labels keep the two kinds of key ID from ever colliding. (The spec said "SHA-256
of the public key"; this adds domain separation and is otherwise identical.) A
signing key is the hybrid pair, so its ID covers both halves.
Every key is in CryptoKit's `rawRepresentation`: for X-Wing the 1216-byte
`ML-KEM-768 encapsulation key (1184) ‖ X25519 public key (32)`, for ML-DSA-65 the
1952-byte FIPS 204 encoding, for Ed25519 the 32-byte RFC 8032 encoding. All have fixed
sizes, so the concatenation is unambiguous. The labels are ASCII with no terminator.
Golden values are in §9.7.

### 6.2 Wrapping the Data Key (HPKE, X-Wing)

- Ciphersuite: `HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256`, base mode.
  X-Wing has no authenticated mode; sender authentication comes from §6.3.
- Exactly, for an independent implementation (RFC 9180 §5.1, §5.2):
  - `mode = mode_base (0x00)`, no PSK (`psk = ""`, `psk_id = ""`);
  - `suite_id = "HPKE" ‖ I2OSP(0x647A, 2) ‖ I2OSP(0x0001, 2) ‖ I2OSP(0x0002, 2)`: KEM X-Wing,
    KDF HKDF-SHA256, AEAD AES-256-GCM (`Nk = 32`, `Nn = 12`);
  - the KEM is **X-Wing as in draft-connolly-cfrg-xwing-kem-06**: `Encap` is its
    `Encapsulate` (1120-byte `enc` = ML-KEM-768 ciphertext ‖ X25519 ephemeral share),
    `Decap` its `Decapsulate`, and the 32-byte shared secret is
    `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")` (label hex `5c2e2f2f5e5c`, last). That
    shared secret goes straight into the HPKE key schedule;
  - `info` is the 32-byte wrap-context **digest** below, not its preimage;
  - `aad` is the raw 32-byte `keyID_i`;
  - the Data Key is sealed once, with sequence number 0 (`nonce = base_nonce`).
- The HPKE `info` can't include the stanzas it helps produce. It is set to the
  **wrap context**, which covers every header field except each stanza's
  `encapsulatedKey` and `wrappedDataKey`:

```
wrapContext = SHA-256( "Chotam v1 wrap context"
                     ‖ prelude (13 bytes, incl. final headerLength)
                     ‖ common fields (80 bytes, incl. commitment)
                     ‖ senderKeyID ‖ recipientCount
                     ‖ keyID_1 ‖ … ‖ keyID_n )
```

- For each recipient: `(enc, ct) = HPKE.seal(pk_i, info = wrapContext, aad = keyID_i, pt = DataKey)`,
  one single-shot HPKE context per recipient (sequence number 0). The export interface
  is not used.
- The stanza stores `keyID_i ‖ enc ‖ ct`.
- **The sender is always a recipient** (encrypt to self, SECURITY.md D21), so a file
  has at most 63 contacts plus the sender.
- **Order:** the writer sorts the contacts' stanzas by key ID (bytewise, ascending), so
  the header reveals nothing about how they were chosen, and puts the sender's stanza
  last. **Readers never rely on stanza order**: they find their own stanza by key ID.
- The Data Key is 32 bytes from the CSPRNG, fresh for every file, and is the IKM of §4.

Binding `wrapContext` means a stanza can't be moved into another file, or into a header
with a different recipient list or commitment.

### 6.3 Trailer: hybrid signature

```
signedMessage = "Chotam v1 signature"
              ‖ headerHash
              ‖ SHA-256(chunk_0 ‖ chunk_1 ‖ … ‖ chunk_{n-1})   (ciphertext, including tags)
              ‖ UInt64BE(n)

trailer = Ed25519.sign(signedMessage) (64) ‖ ML-DSA-65.sign(signedMessage) (3309)   = 3373 bytes
```

- **Both halves must verify** (SECURITY.md D22). ML-DSA-65 is pure FIPS 204 with an
  **empty context string**; Ed25519 is RFC 8032 (pure, not Ed25519ph). Either may be
  randomised by the signer; any valid signature verifies.
- The label differs from the `.pqid` self-signature label (§9.2) from its 11th byte, so
  neither signature can stand in for the other.
- The header hash covers every stanza, so re-targeting a file to new recipients
  invalidates the signature.
- **Who signed:** the reader looks up `senderKeyID` among (a) its own identity and
  (b) its contacts, verified or not, as stored when the file is opened. If it's
  neither, decryption stops with the distinct error "unknown sender" (SECURITY.md D20)
  before any secret is used: the file holds only the sender's key ID, so there is
  nothing to check the signature against. An unverified contact's file opens and is
  reported as unverified.
- **Two passes** (SECURITY.md D19): pass 1 reads the header and the whole body,
  computes `headerHash`, the ciphertext hash and `n`, and verifies the trailer, using
  no secret. Only then is the Data Key unwrapped, the commitment checked, and pass 2
  decrypts. Pass 2 reads the header again and requires the exact same bytes, then
  recomputes the ciphertext hash and `n` from the bytes it actually decrypts and
  requires them, and the trailer, to equal pass 1's, so a file changed between the
  passes fails.
- Password-mode files have no trailer.

## 7. Parser limits, checked before any expensive work

In order:

1. The prelude is complete (13 bytes).
2. The magic matches, `version = 1`, and the mode is known.
3. `headerLength` is within the per-mode range and ≤ 128 KiB.
4. The rest of the header is complete, and nothing is left over.
5. `chunkSize = 65536`, and every fixed field has its exact size.
6. Password mode: `opsLimit` and `memLimit` are in range.
7. Recipient mode: `recipientCount` is in `1…64`, the stanza sizes are exact, and there
   are no duplicate key IDs.

Only after all of that does any expensive or secret work happen:

- **Password mode:** Argon2id, HKDF, the commitment check, then chunk decryption.
- **Recipient mode** (§6.3), in exactly this order:
  1. the reader's identity is unlocked (checked before the file is read; failing it
     says nothing about the file);
  2. the header parses (steps 1–7 above);
  3. find your stanza by key ID. None: **not for you** (the generic failure). This comes
     **before** the sender check, so a file that is both not for you and from an
     unknown sender is reported as not for you;
  4. find the sender by `senderKeyID` among you and your contacts. Neither: **"unknown
     sender"**;
  5. pass 1 reads the whole body and verifies both halves of the signature;
  6. HPKE unwraps the Data Key;
  7. pass 2 re-reads the header (it must be identical), HKDF and the commitment check
     run before any chunk is opened, every chunk is decrypted, and the ciphertext hash,
     chunk count and trailer must equal pass 1's.

Every failure that depends on the file's contents or the key becomes the single public
error **"Decryption failed: file is damaged or not for you."** The one recipient-mode
exception is "unknown sender" (SECURITY.md D20), which reveals only the public
`senderKeyID` and whether it is in the reader's contacts. The detailed reason goes only
to the debug log, as a fixed string that never contains secret material.

## 8. Test vectors

The identity vectors (`.pqid`, passphrase derivation, key IDs, fingerprint) are described in §9.7.

`EncryptionCore/Tests/EncryptionCoreTests/Vectors/` holds password-mode files built by
`make_password_vectors.py`. That script implements this document independently of
the Swift code: the reference Argon2 (argon2-cffi) plus pyca/cryptography for
HKDF-SHA256 and AES-256-GCM. All inputs are fixed, so the output is reproducible.

| File | Size | Contents |
|---|---:|---|
| `password-small.enc` | 190 | `"Chotam golden vector: password mode.\n"`, filename `vector.txt`: one chunk |
| `password-two-chunks.enc` | 65,793 | bytes `i mod 251` for `i` in `0 ..< 65634`, no filename: one full chunk, then a 100-byte final chunk |

Both use the password `correct horse battery staple`, `argon2Salt = 00 01 … 0f`,
`opsLimit = 3`, `memLimit = 256 MiB`, `hkdfSalt = 20 21 … 3f`, `baseNonce = 40 41 … 4b`.

**Recipient mode** (Phase 5b): `make_recipient_vectors.py` builds two files between the
golden identity Alice (§9.7) and a second golden identity, Bob, independently of the
Swift code. X-Wing encapsulation and decapsulation are written from
draft-connolly-cfrg-xwing-kem-06 (ML-KEM-768 from kyber-py) and checked against the
draft's three published test vectors. OpenSSL's ML-KEM-768 must decapsulate every
ML-KEM ciphertext to the same secret. The HPKE key schedule and seal are written from
RFC 9180 and checked against its official vector for base mode, HKDF-SHA256 and
AES-256-GCM (there are no published HPKE vectors with X-Wing, so only the KEM differs
from that vector). Both signature halves are checked with OpenSSL too, and the script
opens every file again, through §7's steps, as each recipient, before writing it. The
X-Wing encapsulation seeds are fixed (`SHA-512("Chotam golden eseed " ‖ tag ‖ index)`),
so the files are reproducible.

| File | Size | Contents |
|---|---:|---|
| `identity-bob-v1.pqid` | 6,632 | Bob: passphrase `angrily copy excretion joyride perish scouting tipped`, `kdfSalt = b0 b1 … bf`, ops 3, 256 MiB, name `Bob`; fingerprint `KYVS TWF6 1AFH B7H7 2J9D MM1B VYCG MJ1A`; SHA-256 `8cac900b…040788f0f` |
| `recipients-from-alice.enc` | 5,973 | Alice → Bob (and Alice), signed by Alice: `"Chotam golden vector: recipient mode.\n"`, filename `vector.txt`, one chunk. Data Key `c0 c1 … df`, `hkdfSalt = 60 61 … 7f`, `baseNonce = 80 81 … 8b`. SHA-256 `1a803e8e…2d8746bcb3` |
| `recipients-from-bob.enc` | 71,575 | Bob → Alice (and Bob), signed by Bob: bytes `i mod 251` for `i` in `0 ..< 65634`, no filename, a full chunk then a 100-byte final chunk. Data Key `e0 e1 … ff`, `hkdfSalt = 30 31 … 4f`, `baseNonce = 50 51 … 5b`. SHA-256 `d8e9b355…b02a1ba21` |

Bob's encryption key ID is `4c2072ed26b99aff222a574009b173407c0e89e5849f142d3b0903c8cda69c1a`,
his signing key ID `7294d21b83a43861a72c13e5d14007c629879124c86f57a9b4c596148968a44e`.

## 9. Public identity file (`.pqid`), version 1

A public identity is what users exchange so they can encrypt to each other and check
each other's signatures. It holds **public data only**: three public keys, the public
parameters for re-deriving the identity from its owner's passphrase (§9.6), an optional
name and a self-signature. It travels as a `.pqid` file, or as a copyable string:
standard Base64 (RFC 4648 §4, with padding) of exactly the same bytes.

### 9.1 Layout

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `CHOTAMID` |
| 8 | 2 | version | must be `1` (anything else: "made by a newer version") |
| 10 | 2 | encryptionKeyLength | must equal `1216` |
| 12 | 1216 | encryptionKey | X-Wing public key (§6.1) |
| 1228 | 2 | mldsaKeyLength | must equal `1952` |
| 1230 | 1952 | mldsaKey | ML-DSA-65 public key |
| 3182 | 2 | ed25519KeyLength | must equal `32` |
| 3184 | 32 | ed25519Key | Ed25519 public key |
| 3216 | 1 | kdfAlgorithm | `1` = Argon2id v1.3 (§9.6); anything else: "made by a newer version" |
| 3217 | 1 | kdfFlags | bit 0 = a key file is needed (§9.6); any other bit set: "made by a newer version" |
| 3218 | 8 | opsLimit | `3 … 16` |
| 3226 | 8 | memLimit | bytes, `256 MiB … 2 GiB` |
| 3234 | 1 | parallelism | must be `1` (libsodium's Argon2id uses one lane) |
| 3235 | 16 | kdfSalt | random, chosen when the identity is created |
| 3251 | 1 | nameLength | `0 … 64`; `0` means no name |
| 3252 | n | name | UTF-8, the owner's suggested name |
| 3252 + n | 2 | extensionsLength | `0 … 1024` |
| 3254 + n | e | extensions | §9.5; none are defined in v1 |
| 3254 + n + e | 2 | signatureLength | must equal `3373` |
| 3256 + n + e | 3373 | selfSignature | §9.2 |

Total size: `6629 + n + e` bytes, so `6629 … 7717`.

The name must be strict UTF-8, 1–64 bytes, not only whitespace, and without C0/C1 control
characters or Unicode bidirectional controls (the same rule as §3). It is **untrusted
text**, shown only as a suggestion when importing. The user picks the contact's actual
name, and keys are identified only by key IDs and fingerprints, never by name.

The KDF bounds stop a substituted `.pqid` from making an unlock trivially cheap or
asking for minutes of work or many GiB of memory. They only matter for your **own**
`.pqid`: nobody ever derives a contact's keys.

### 9.2 Self-signature

```
message       = "Chotam v1 identity signature" ‖ bytes[0 ..< 3254 + n + e]
selfSignature = Ed25519.sign(ed25519Key, message) (64) ‖ ML-DSA-65.sign(mldsaKey, message) (3309)
```

- **Both halves must verify** (SECURITY.md D22). ML-DSA-65 is pure FIPS 204 with an
  empty context string; Ed25519 is RFC 8032. The label gives domain separation: it
  differs from the file-signature label (§6.3) from its 11th byte.
- It covers every byte before `signatureLength`: magic, version, the three keys, the KDF
  block, the name and the extensions.
- It proves the holder of both signing keys vouches for `encryptionKey`, the KDF
  parameters and the name, so nobody can publish an identity that pairs **someone
  else's signing key** with their own encryption key (SECURITY.md D14).
- It says nothing about **who** that holder is. Only comparing fingerprints (§9.3) does.
- Signatures may be randomised, so two exports of the same identity can differ byte for
  byte. Chotam signs once, when the identity is created, and stores the result.

### 9.3 Fingerprint

```
digest      = SHA-256("Chotam v1 identity fingerprint" ‖ encryptionKey (1216) ‖ mldsaKey (1952) ‖ ed25519Key (32))
fingerprint = CrockfordBase32(digest[0 ..< 20])        160 bits → 32 symbols
display     = 8 groups of 4 symbols, separated by spaces
```

- **Crockford base32** alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O or U).
  The bits are taken most significant first, 5 per symbol; 160 is a multiple of 5, so
  there is no padding.
- It covers **all three** public keys, because a user who verifies a contact trusts all
  of them. It covers nothing else: renaming a contact, new KDF parameters or a new
  self-signature never change it.
- Fixed-length fields after a fixed label, so the concatenation is unambiguous. The label
  keeps fingerprints apart from key IDs (§6.1).
- **Comparing:** both people read all 8 groups aloud, in order, for example on a call
  where they recognise each other's voice, and check every symbol. The UI numbers the
  groups. When a fingerprint is typed rather than read, Chotam compares it the Crockford
  way: case, spaces and hyphens don't matter, `O` counts as `0`, and `I` or `L` as `1`.
  All 32 symbols must match; there is no partial match.

### 9.4 Parser rules, in order

1. The input is at most 8 KiB (file) or 12 KiB (string). Larger input is refused unread.
2. String form only: ASCII spaces, tabs and line breaks are removed; the rest must be
   standard Base64 with correct padding and zero spare bits (one canonical string per
   identity).
3. The magic matches and `version = 1`.
4. Every key length field has its exact value.
5. The KDF block: `kdfAlgorithm = 1` and no unknown flag (else "newer version");
   `parallelism = 1`, and `opsLimit` and `memLimit` within their ranges.
6. The name follows §9.1.
7. The extensions follow §9.5; an unknown critical one means "newer version".
8. `signatureLength = 3373`, and nothing follows the signature.
9. Every ML-KEM-768 coefficient in `encryptionKey[0 ..< 1152]` is below `q = 3329`
   (FIPS 203 §7.2 modulus check). Chotam checks this itself, on every platform.
10. All three keys parse (CryptoKit).
11. Both halves of the self-signature verify.

Only then is the identity accepted. It is still **unverified** until the user compares
its fingerprint (SECURITY.md D5).

### 9.5 Extensions (reserved)

Reserved so a later version can add fields (for example a "live mode" in which the
identity signs short-lived per-transfer keys) without a new `.pqid` version:

```
extensions = entry*        entry = type (u16) ‖ length (u16) ‖ value (length bytes)
```

- Entries are in strictly increasing `type` order; `type = 0` is not used. So each set
  of extensions has exactly one encoding.
- Bit 15 of `type` marks a **critical** extension. A reader that doesn't know a
  critical extension refuses the identity as "made by a newer version"; an unknown
  non-critical one is ignored (it stays covered by the self-signature).
- v1 defines **no** extensions, so v1 writers emit `extensionsLength = 0`.
- Live mode would also need changes to the `.enc` header; those aren't reserved here.

### 9.6 Passphrase-derived identity

An identity is **derived from a passphrase** and nothing secret is ever stored
(SECURITY.md D17, D18). The `.pqid` carries everything else needed to rebuild it on any
Mac.

```
passphrase = 7…10 distinct words from the EFF large wordlist, generated by Chotam
canonical  = the words, lowercased, joined by single ASCII spaces (UTF-8)
master     = Argon2id(canonical, kdfSalt, opsLimit, memLimit)                32 bytes
ikm        = master                                                          no key file
           = master ‖ SHA-256("Chotam v1 key file" ‖ key file contents)      kdfFlags bit 0
xwingSeed   = HKDF-SHA256(ikm, salt = kdfSalt, info = "Chotam v1 identity X-Wing seed",    L = 32)
mldsaSeed   = HKDF-SHA256(ikm, salt = kdfSalt, info = "Chotam v1 identity ML-DSA-65 seed", L = 32)
ed25519Seed = HKDF-SHA256(ikm, salt = kdfSalt, info = "Chotam v1 identity Ed25519 seed",   L = 32)
contactsKey = HKDF-SHA256(ikm, salt = kdfSalt, info = "Chotam v1 contacts key",            L = 32)
```

- **Argon2id** is exactly as in §4.1 (libsodium `crypto_pwhash`, `ALG_ARGON2ID13`, one
  lane, no secret or associated data), with this identity's parameters. A new identity
  uses `opsLimit = 8`, `memLimit = 1 GiB`, and a fresh random 16-byte salt (libsodium's
  fixed salt size).
- **Canonical form:** the typed text is NFC-normalised, lowercased and split on any
  whitespace. It must be 7 to 10 words, all different, all in the wordlist (the four
  hyphenated EFF words count as one word each). So case and spacing never matter.
- **Keys:** `xwingSeed` is X-Wing's 32-byte decapsulation-key seed (CryptoKit
  `seedRepresentation`, draft-connolly-cfrg-xwing-kem); `mldsaSeed` is FIPS 204's ξ;
  `ed25519Seed` is the RFC 8032 private key. The distinct labels make the four outputs
  independent: the keys never share material.
- **Unlocking** recomputes the three public keys and requires them to equal the
  `.pqid`'s exactly. Anything else is "wrong passphrase or key file", and the derived
  keys are dropped.
- **The key file** can be any non-empty file. It is hashed as a stream, so its size
  doesn't matter. Without it the identity can't be rebuilt.
- The same passphrase with a new salt is a different identity. Changing the passphrase
  means a new identity.

### 9.7 Test vectors

`EncryptionCore/Tests/EncryptionCoreTests/Vectors/identity-v1.pqid` and
`identity-keyfile-v1.pqid`, built by `make_identity_vectors.py` independently of the
Swift code: Argon2id from argon2-cffi (the reference implementation), HKDF from
pyca/cryptography checked against a hand-written RFC 5869 HKDF, X-Wing key generation
from the draft's seed expansion (checked against the draft's own test vectors),
ML-KEM-768 from kyber-py, ML-DSA-65 from dilithium-py, Ed25519 from pyca/cryptography,
and OpenSSL (via pyca/cryptography) as a second implementation of ML-KEM-768 and
ML-DSA-65. Both signatures are deterministic, so the files are reproducible.

| Value | |
|---|---|
| passphrase (as typed) | `"  Agreement curve\tflakily  LIGAMENT pretty shrimp unbundle "` |
| canonical passphrase | `agreement curve flakily ligament pretty shrimp unbundle` |
| kdfSalt | `a0 a1 … af` (16 bytes) |
| opsLimit, memLimit | `3`, `256 MiB` (the cheapest accepted, so tests stay fast) |
| master | `56699a39a9c4c3fb4d2ae00b01c7e5d35e93d56ab43894dcd504c4a382d17bb0` |
| xwingSeed | `50982133f3fc11b35a7d74bd199e71ae2d32f7eff28ee9e41dfab1319c339e01` |
| mldsaSeed | `d73865dc9d34f90dc0a3285705e191567e33c975fe2088578a9ba416239a2029` |
| ed25519Seed | `ca4929a785c811281ff92dfee6f0ffe722c6dd8d73fa5cd0424b039fbbb062e8` |
| contactsKey | `f7a103cafe4651cab5a16abc925db3bac5b4bb00368303905c3258cbc4d5179a` |
| SHA-256(X-Wing public key) | `1e34d8c2c31e5034107adc9a9d9cd835f6f3bdbbda90c7f3f49dfb79308fe5aa` |
| SHA-256(ML-DSA-65 public key) | `2d47a737b8b0cd79b1664bbcf3560c59d0c079c072b0570863b917a6cd38d2cf` |
| Ed25519 public key | `a6ea84d3af13fddb9ea74b418494d456844e44cd4686dced46066264550246be` |
| encryptionKeyID | `8e8b1793835f7461f1e4e32dd9479886c952a5984b1eb36b1be2f22dd33a186f` |
| signingKeyID | `21e85ceeb2d426639b1464dade0766deaefb2646b254a67a2f18fb9e96333263` |
| digest[0 ..< 20] | `403bdefa3bd55bc9d3bcbc8329f8740676bbeb74` |
| fingerprint | `80XX XYHV TNDW KMXW QJ1J KY3M 0SVB QTVM` |
| name | `Alice` |
| file | 6,634 bytes, SHA-256 `e752f0cc3ceba81971690e964dd1578f6a69586d58bf1fec157af71185c345a3` |

The key-file vector uses the same passphrase, salt and cost with a 1 KiB key file
(bytes `00 01 … ff`, four times) and `kdfFlags = 1`: X-Wing seed
`efdd6b690a140abedc42877315f2583c5b39b36e1b609a9abbefd816fad7c962`, fingerprint
`PXJ3 2BC0 R2CV ZNDE BMXP RPPQ 6WM9 HK6D`, file SHA-256
`9a814bf6f3fd1ba2c6759ee34dd3b6ce464635b5892a229c98a39c8d17eed6ad`.

## 10. Files Chotam keeps on the Mac (local, not exchanged)

Chotam **never uses the Keychain** (SECURITY.md D18). It keeps two files in one folder
(the app's container in the app), both owner-only (mode 0600), both written atomically
(temp file, flush, rename):

| File | Contents | Secret? |
|---|---|---|
| `identity.pqid` | your public identity, exactly as §9 (it carries the KDF salt, so unlocking needs only the passphrase) | no |
| `contacts.chotam` | your contacts, encrypted and authenticated with `contactsKey` (§9.6) | no: encrypted |

**`identity.pqid`** is parsed like any import. A damaged or substituted one can't unlock:
the derived keys wouldn't match it. Creating or restoring an identity writes it with an
exclusive rename, so an existing identity is never overwritten. Any `contacts.chotam`
left without its identity is deleted first.

**`contacts.chotam`, version 1:**

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `CHOTAMCF` |
| 8 | 2 | version | must be `1` |
| 10 | 32 | owner | your `encryptionKeyID`; another value means another identity's file |
| 42 | 12 | nonce | random, fresh for every save |
| 54 | … | ciphertext ‖ tag | AES-256-GCM(`contactsKey`, nonce, aad = bytes `0 ..< 54`) |

```
plaintext = count (u16, 0…500)
          ‖ count × ( verified (u8: 0 or 1) ‖ nameLength (u8, 1…64) ‖ name ‖ pqidLength (u16) ‖ the contact's .pqid )
```

- At most 4 MiB, refused unread if larger.
- A file that is too short, has the wrong magic, version or owner, or doesn't
  authenticate is "damaged"; so is any structural error inside the plaintext.
- Each embedded `.pqid` is re-parsed by §9.4, self-signature included, on every load. An
  entry whose name or `.pqid` no longer passes is skipped (and logged at debug level),
  so one bad entry can't hide the others. So is an entry sharing any key with you or an
  earlier contact.
- **Not detected:** replacing the file with an older copy of itself (SECURITY.md §5.24).
