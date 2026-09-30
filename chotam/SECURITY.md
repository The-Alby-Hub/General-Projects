# Chotam security model

This document says what Chotam protects, what it doesn't, and what is known to be
imperfect. It is kept honest on purpose: a gap listed here is better than one a user
discovers the hard way. The byte-level format is in [FORMAT.md](FORMAT.md).

## 1. What Chotam is for

It encrypts **individual local files** on a Mac, so they can sit on disk, go on a USB
stick, or travel over email or cloud storage and stay confidential and tamper-evident,
including against an adversary with a future quantum computer.

It is fully offline. It has no network code, no server, no telemetry, and no system or
file-system extensions.

## 2. Assets

| Asset | Where it lives |
|---|---|
| File contents and original filename | Encrypted in the `.enc` body (FORMAT §3) |
| Passwords | Typed by the user; never stored |
| Identity private keys (X-Wing, ML-DSA-65) | Secure Enclave or Keychain, never exported (Phase 4) |
| Contact public keys and their verified status | Local app storage (Phase 4) |
| Per-file Data Keys and file keys | Memory only, for the duration of one operation |

## 3. Adversaries

| # | Adversary | Capabilities |
|---|---|---|
| A1 | **Thief or finder** | Gets `.enc` files: a lost laptop without FileVault, a USB stick, a cloud account. |
| A2 | **Harvest-now-decrypt-later** | Records `.enc` files today, and has a large quantum computer later. |
| A3 | **Active tamperer** | Modifies, truncates, reorders, splices or replaces `.enc` files in transit or at rest. |
| A4 | **Malicious sender** | Crafts hostile files, e.g. to crash the parser, exhaust memory or CPU, or make one file decrypt differently for different recipients. |
| A5 | **Malicious recipient or insider** | Legitimately receives a file and tries to reuse it: forward it as if newly signed, or re-target it. |
| A6 | **Impostor** | Tries to get the user to trust a public identity that isn't the claimed person's. |

## 4. What Chotam protects against

| Threat | Protection | Adversary |
|---|---|---|
| Reading file contents or the original filename | AES-256-GCM. The filename sits inside the encrypted stream. | A1, A2 |
| Quantum attack on the key exchange | HPKE with X-Wing (ML-KEM-768 + X25519 hybrid): both parts would have to be broken. | A2 |
| Quantum attack on the symmetric layer | 256-bit keys. Grover's algorithm leaves about 128-bit security. | A2 |
| Quantum attack on the password | Argon2id at about 1 GiB of memory. Grover gives at most a square-root speed-up on a password's entropy, so this holds **only for strong passwords**. The minimum-strength rule and the generator exist for this reason. | A2 |
| Forged or impersonated sender | ML-DSA-65 signature over the header and all ciphertext, checked against a **verified** contact. | A3, A6 |
| Bit flips, splicing, reordering, truncation, appended data | Per-chunk GCM tags with AAD = header hash, index and final flag (FORMAT §5.3), plus the signature in recipient mode. | A3 |
| One ciphertext decrypting differently for different recipients | Key-commitment tag, checked before any chunk is opened (FORMAT §4.2), plus the signature. | A4 |
| Parser crashes and resource exhaustion | Strict bounded parser. The prelude is checked before any allocation, then sizes, then counts ≤ 64, then Argon2id limits, **before** any key derivation (FORMAT §7). Fuzz-tested. | A4 |
| Moving a wrapped key into another file | HPKE `info` = wrap context; HPKE AAD = recipient key ID (FORMAT §6.2). | A3, A4 |
| Re-targeting a signed file to new recipients | The signature covers the header, including every stanza. | A5 |
| Error messages as an oracle | One generic error for every failure. Details go only to the debug log, as fixed strings. | A3, A4 |
| Trusting the wrong key | Fingerprints, imported contacts start unverified, and an explicit confirmation to encrypt to an unverified contact (Phase 4). | A6 |
| Half-written or corrupted outputs | Temp file, then an atomic replace. The original is never touched on failure (Phase 3). | — |

## 5. What Chotam does NOT protect against

1. **A compromised Mac.** Malware, a keylogger, a malicious admin, or anyone who can
   read the app's memory while it runs sees passwords, keys and plaintext. Nothing
   in user space can fix this.
2. **Weak passwords.** Argon2id slows guessing down; it doesn't make `summer2024`
   safe. Password mode is only as strong as the password.
3. **Metadata.** These stay visible:
   - the file's size (the ciphertext is the plaintext size plus about 16 bytes per
     64 KiB and a fixed header);
   - timestamps and extended attributes set by the file system;
   - the `.enc` file's own name;
   - the fact that Chotam was used (the magic bytes);
   - in recipient mode, the **key IDs of all recipients and of the sender**. Anyone who
     has those public keys can see who a file was sent to and who signed it.

   Hiding recipients is possible in a future version.
4. **Secure deletion.** On APFS and SSDs, overwriting a file doesn't reliably erase the
   old blocks (copy-on-write, snapshots, wear levelling, Time Machine). Chotam never
   deletes originals by itself and doesn't claim to wipe them. **Use FileVault.** It is
   the only thing that protects deleted plaintext remnants and temp files.
5. **Password mode doesn't authenticate the sender.** Anyone who knows the password can
   create a valid file. Integrity holds only against people who don't know it.
6. **Rollback and replay.** An attacker can swap a `.enc` file for an **older, genuine**
   one from the same sender. There is no global counter or timestamp to detect this.
7. **A compromised sender key.** A stolen ML-DSA key can sign files until the contact
   is removed. There is no revocation infrastructure; the design is offline.
8. **No deniability.** An ML-DSA signature is transferable proof that the sender's key
   signed the file. A recipient can show it to third parties.
9. **ML-DSA-65 is not a hybrid signature.** Encryption is hybrid (X-Wing), but signing
   relies on ML-DSA-65 alone (FIPS 204). If ML-DSA were broken, sender authentication
   would fail even against a classical attacker, though confidentiality would not. A
   hybrid Ed25519 + ML-DSA-65 signature is an open option for Phase 5.
10. **Side channels outside our code.** We rely on CryptoKit's and libsodium's
    implementations. Our own secret comparisons are constant-time (§7.2).
11. **Coercion.** Anyone who can compel the user to reveal a password or unlock the Mac
    gets the plaintext.
12. **Memory hygiene is best-effort.** See §7.3.

## 6. Design notes and deviations from the original spec

Each of these was flagged before any code was written.

| # | Topic | Decision |
|---|---|---|
| D1 | **Filename in the header** | The spec put it in the plaintext header, which leaks the name. It now goes in an encrypted metadata record (FORMAT §3). |
| D2 | **HPKE `info` was circular** | The header can't bind its own wrapped keys, so `info` is a defined "wrap context" hash (FORMAT §6.2). |
| D3 | **Key IDs** | Domain-separated SHA-256 of the raw public key, so encryption and signing IDs can never collide (FORMAT §6.1). |
| D4 | **Argon2id parameters from a file are attacker-controlled** | Hard ranges are enforced before running Argon2id (FORMAT §2.3). |
| D5 | **Fingerprint length** | 8 groups of 4 **hex** characters is only 128 bits: a quantum second-preimage search (Grover) costs about 2^64. Proposal: 8 × 4 **Crockford base32** = 160 bits (about 2^80), same visual length. Decided in Phase 4. |
| D6 | **"≥ 14 characters" accepts `aaaaaaaaaaaaaa`** | Phase 2 adds dependency-free checks: repeats, sequences, a common-password list. The passphrase generator needs a wordlist (e.g. EFF large list, CC-BY data); it will be approved first. |
| D7 | **Secure Enclave coverage** | Per Apple (WWDC25 session 314), the Secure Enclave supports ML-KEM and ML-DSA. X-Wing includes X25519, which the Secure Enclave doesn't provide. Expected result: **ML-DSA-65 in the Secure Enclave, X-Wing private key in the Keychain** (`WhenUnlockedThisDeviceOnly` + user presence). Confirmed against the real SDK in Phase 4. |
| D8 | **Keychain entitlement** | The data-protection keychain and the Secure Enclave need a signed app with a `keychain-access-groups` entitlement. This is needed in addition to `user-selected read-write`. Keychain and Secure Enclave tests need an app-hosted Xcode test target; `swift test` can't reach them. |
| D9 | **Sandbox and sibling files** | `user-selected read-write` grants access to the chosen file, not its folder, so `Document.pdf.enc` can't be created beside it without more. Plan: an NSSavePanel prefilled with the `.enc` name (or user-granted folder access). The temp file goes in `FileManager.url(for: .itemReplacementDirectory, …)` on the same volume, then `replaceItemAt`; a new file uses a no-overwrite rename. Phase 3/6. |
| D10 | **Unverified plaintext on disk** | Proposal for Phase 5: pass 1 verifies the signature over the ciphertext only; pass 2 decrypts to a temp file and checks the ciphertext hash hasn't changed. Plaintext of a forged file is then never written. Some plaintext still touches the temp file before the final chunk is checked (see 5.4). |

## 7. Implementation hygiene

### 7.1 Randomness
- Salts, nonces and Data Keys come from CryptoKit's CSPRNG (`SymmetricKey(size:)`),
  which is `SecRandomCopyBytes` on Apple platforms.

### 7.2 Constant-time comparison
- Secret-dependent comparisons (the commitment tag) use an XOR-accumulate loop with no
  early exit and no data-dependent branches.
- Lengths are public and compared normally.
- Swift makes no formal constant-time guarantee about generated code. The function is
  `@inline(never)` and simple enough that we have no reason to expect branches, but
  this is best-effort.

### 7.3 Zeroisation: best-effort, with known limits
- Keys stay in `SymmetricKey`, whose storage CryptoKit zeroes on release.
- Our own plaintext and key buffers are wiped after use: with `memset_s` on Apple
  platforms, which the compiler may not remove, and a plain fill on the Linux test
  build.
- **Limits:**
  - Swift arrays and `Data` are copy-on-write and may be copied by the runtime or by
    Foundation, and those copies can't be tracked.
  - Strings, including passwords from SwiftUI text fields, are immutable and can't be
    wiped.
  - The OS may page memory to swap. macOS encrypts swap, and FileVault covers the disk.

### 7.4 Errors and logging
- Every decryption failure maps to the single public message.
- Detailed reasons are fixed enum strings, logged at debug level via `os.Logger`, and
  never include key material, passwords, plaintext or filenames.

### 7.5 Dependencies
- Apple CryptoKit (system framework).
- libsodium for Argon2id only (Phase 2), with its version pinned.
- apple/swift-crypto and swift-asn1 are declared **only when building on Linux**, so the
  core can be tested in a Linux container. They are not declared, fetched or linked on
  macOS.
