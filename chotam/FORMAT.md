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
| Recipient-mode stanzas (HPKE X-Wing) | yes | fields parsed in Phase 1, HPKE in Phase 5 |
| Trailer (ML-DSA-65 signature) | yes | framing in Phase 1, signing in Phase 5 |
| Key IDs (§6.1) | yes | Phase 4 |
| Public identity file `.pqid` and fingerprints (§9) | yes | Phase 4 |
| Keychain records for your identity and contacts (§10) | yes | Phase 4 |

Sizes marked **(verify)** come from the relevant standard and are rechecked against
the macOS 26 SDK when the phase that uses them is implemented. If the SDK differs,
the format is corrected before it is ever used to write a file; it is not frozen
until Phase 7. Phase 4 added tests that assert them on the SDK (`IdentityKeyTests`:
X-Wing public key 1216, encapsulated key 1120, HPKE-wrapped Data Key 48, ML-DSA-65
public key 1952, signature 3309). The marks are removed once those pass on macOS.

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
| trailer              |  recipient mode only: ML-DSA-65 signature
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
| 32 | senderKeyID | signing-key ID of the sender (§6.1) |
| 1 | recipientCount | `1…64` |
| 1204 × count | stanzas | see below |

Each stanza:

| Size | Field | Rule |
|---:|---|---|
| 32 | keyID | recipient's encryption-key ID (§6.1); no duplicates within a header |
| 2 | encLength | must equal `1120`, the X-Wing encapsulated-key size **(verify)** |
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
mode, see §6.3 for recipient mode), the reader keeps a read-ahead buffer:

- If more than `S + T` bytes remain, the next `S` bytes are a **non-final** chunk.
- Otherwise the input has ended. The remaining bytes are the **final** chunk followed by
  exactly `T` trailer bytes. The final chunk must be at least 16 bytes.

The reader never reads more than `S + T + 1` bytes at a time.

## 6. Recipient mode (implemented in Phase 5)

### 6.1 Key IDs (implemented in Phase 4)

```
encryptionKeyID = SHA-256("Chotam v1 encryption key id" ‖ XWing public key, raw representation)
signingKeyID    = SHA-256("Chotam v1 signing key id"    ‖ ML-DSA-65 public key, raw representation)
```

The labels keep the two kinds of key ID from ever colliding. (The spec said "SHA-256
of the public key"; this adds domain separation and is otherwise identical.)
"Raw representation" is CryptoKit's `rawRepresentation`: for X-Wing the 1216-byte
`ML-KEM-768 encapsulation key (1184) ‖ X25519 public key (32)`, for ML-DSA-65 the
1952-byte FIPS 204 encoding. The labels are ASCII with no terminator. Golden values
are in §9.4.

### 6.2 Wrapping the Data Key (HPKE, X-Wing)

- Ciphersuite: `HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256`, base mode.
  X-Wing has no authenticated mode; sender authentication comes from §6.3.
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

- For each recipient: `(enc, ct) = HPKE.seal(pk_i, info = wrapContext, aad = keyID_i, pt = DataKey)`.
- The stanza stores `keyID_i ‖ enc ‖ ct`.

Binding `wrapContext` means a stanza can't be moved into another file, or into a header
with a different recipient list or commitment.

### 6.3 Trailer: ML-DSA-65 signature

```
signedMessage = "Chotam v1 signature"
              ‖ headerHash
              ‖ SHA-256(chunk_0 ‖ chunk_1 ‖ … ‖ chunk_{n-1})   (ciphertext, including tags)
              ‖ UInt64BE(n)

trailer = ML-DSA-65.sign(senderSigningKey, signedMessage)      (3309 bytes (verify))
```

- The header hash covers every stanza, so re-targeting a file to new recipients
  invalidates the signature.
- The reader looks up `senderKeyID` among trusted contacts, verifies the signature, and
  releases the output only after both the signature and every chunk verify.
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

Only after all of that does key derivation (HKDF, Argon2id or HPKE) happen, then the
commitment check, then chunk decryption.

Every failure, at any stage, becomes the single public error
**"Decryption failed: file is damaged or not for you."** The detailed reason goes only
to the debug log, as a fixed string that never contains secret material.

## 8. Test vectors

The identity vector (`.pqid`, key IDs, fingerprint) is described in §9.5.

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

## 9. Public identity file (`.pqid`), version 1

A public identity is what users exchange so they can encrypt to each other and check
each other's signatures. It holds **public keys only**, never private material. It
travels as a `.pqid` file, or as a copyable string: standard Base64 (RFC 4648 §4, with
padding) of exactly the same bytes.

### 9.1 Layout

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `CHOTAMID` |
| 8 | 2 | version | must be `1` (anything else: "made by a newer version") |
| 10 | 2 | encryptionKeyLength | must equal `1216` |
| 12 | 1216 | encryptionKey | X-Wing public key, raw representation (§6.1) |
| 1228 | 2 | signingKeyLength | must equal `1952` |
| 1230 | 1952 | signingKey | ML-DSA-65 public key, raw representation |
| 3182 | 1 | nameLength | `0 … 64`; `0` means no name |
| 3183 | n | name | UTF-8, the owner's suggested name |
| 3183 + n | 2 | signatureLength | must equal `3309` |
| 3185 + n | 3309 | selfSignature | see §9.2 |

Total size: `6494 + n` bytes, so `6494 … 6558`.

The name must be strict UTF-8, 1–64 bytes, not only whitespace, and without C0/C1 control
characters or Unicode bidirectional controls (the same rule as §3). It is **untrusted
text**, shown only as a suggestion when importing. The user picks the contact's actual
name, and keys are identified only by key IDs and fingerprints, never by name.

### 9.2 Self-signature

```
selfSignature = ML-DSA-65.sign(signingKey, "Chotam v1 identity signature" ‖ bytes[0 ..< 3183 + n])
```

- It is pure ML-DSA-65 (FIPS 204) with an empty context string. The label gives domain
  separation: it differs from the file-signature label (§6.3) from its 11th byte.
- It covers every byte before `signatureLength`: magic, version, both keys and the name.
- It proves the holder of `signingKey` vouches for `encryptionKey` and the name, so
  nobody can publish an identity that pairs **someone else's signing key** with their
  own encryption key (SECURITY.md D14).
- It says nothing about **who** that holder is. Only comparing fingerprints (§9.3) does.
- ML-DSA signatures may be randomised, so two exports of the same identity can differ
  byte for byte. Chotam signs once, when the identity is created, and stores the result.

### 9.3 Fingerprint

```
digest      = SHA-256("Chotam v1 identity fingerprint" ‖ encryptionKey (1216) ‖ signingKey (1952))
fingerprint = CrockfordBase32(digest[0 ..< 20])        160 bits → 32 symbols
display     = 8 groups of 4 symbols, separated by spaces
```

- **Crockford base32** alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O or U).
  The bits are taken most significant first, 5 per symbol; 160 is a multiple of 5, so
  there is no padding.
- It covers **both** public keys, because a user who verifies a contact trusts both. It
  covers nothing else: renaming a contact or re-signing the `.pqid` never changes it.
- Fixed-length fields after a fixed label, so the concatenation is unambiguous. The label
  keeps fingerprints apart from key IDs (§6.1), which hash one key each.
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
4. Every length field has its exact value; the name follows §9.1; nothing follows the
   signature.
5. Every ML-KEM-768 coefficient in `encryptionKey[0 ..< 1152]` is below `q = 3329`
   (FIPS 203 §7.2 modulus check). Chotam checks this itself, on every platform.
6. Both keys parse (CryptoKit).
7. The self-signature verifies.

Only then is the identity accepted. It is still **unverified** until the user compares
its fingerprint (SECURITY.md D5).

### 9.5 Test vector

`EncryptionCore/Tests/EncryptionCoreTests/Vectors/identity-v1.pqid`, built by
`make_identity_vectors.py` independently of the Swift code: X-Wing key generation from
the draft's seed expansion (checked against the draft's own test vectors), ML-KEM-768 from
kyber-py, ML-DSA-65 from dilithium-py, and OpenSSL (via pyca/cryptography) as a second
implementation of both. The signature is ML-DSA's deterministic variant, so the file is
reproducible.

| Value | |
|---|---|
| X-Wing seed | `60 61 … 7f` (32 bytes) |
| ML-DSA-65 seed (ξ) | `80 81 … 9f` (32 bytes) |
| name | `Alice` |
| SHA-256(X-Wing public key) | `d13209d86547a31ae86a67d9a26c90e5efc1310514195ab06e9b9e12bf328b6a` |
| SHA-256(ML-DSA-65 public key) | `e00c3ad05e18901d30ebc2c9044f4b0756ae6922ff258d688292e8ead8d4a2d5` |
| encryptionKeyID | `19e469ef9a47e5d47b905b1f363d49d62394fec96d55fa6574214f41d65fd2bd` |
| signingKeyID | `68b63822246c6146ecf92cd83e96fd9d3a78d795ca9a59a9ca53a3b5cbd751ef` |
| digest[0 ..< 20] | `b196c8d1de4e5595b9406c2790f8717b6c9df574` |
| fingerprint | `P6BC HMEY 9SAS BEA0 DGKS 1Y3H FDP9 VXBM` |
| file | 6,499 bytes, SHA-256 `2f3016a2e1d19d27202dfc29ef49c71eb9eba5e2a9d271b661b3cb05c3f47fad` |

## 10. Keychain records (local storage, not exchanged)

Chotam keeps its identity and contacts as generic-password items in the data-protection
Keychain (SECURITY.md D7, D15). Every item is `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
and not synchronizable. The private-key items also need user presence for every read.

| Service | Account | Contents | Extra protection |
|---|---|---|---|
| `app.chotam.identity` | `encryption` | X-Wing private key, CryptoKit `integrityCheckedRepresentation` (seed ‖ SHA3-256 of the public key, 64 bytes) | user presence |
| `app.chotam.identity` | `signing` | Secure Enclave: the key's `dataRepresentation` (a handle only this Mac's Secure Enclave can use). Keychain fallback: the ML-DSA-65 `integrityCheckedRepresentation` (64 bytes) | Secure Enclave: the key's own access control (user presence). Fallback: user presence |
| `app.chotam.identity` | `public` | own-identity record, below | none |
| `app.chotam.contacts` | hex of the contact's `encryptionKeyID` | contact record, below | none |

**Own-identity record:**
`"CHOTAMME" ‖ version = 1 (u16) ‖ signingKeyStorage (u8: 1 = Secure Enclave, 2 = Keychain)
‖ pqidLength (u16) ‖ your .pqid`. It is written **last** when an identity is created,
and deleted **first** when it is deleted, so its presence is what makes an identity exist.

**Contact record:**
`"CHOTAMCT" ‖ version = 1 (u16) ‖ verified (u8: 0 or 1) ‖ nameLength (u8, 1…64) ‖ name
‖ pqidLength (u16) ‖ the contact's .pqid`.

Both are parsed as strictly as an import: exact lengths, no trailing bytes, and the
embedded `.pqid` goes through §9.4 again, signature included. A contact record must be
stored under its own key ID. A damaged or misfiled contact is skipped (and logged at
debug level), so one bad item can't hide the others.
