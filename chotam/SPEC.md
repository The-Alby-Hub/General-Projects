# Chotam: project specification

This is the original project brief, kept verbatim below so any new session can
work from it. **Decisions made since then override the brief where they differ.**
They're listed first.

## Decisions and deviations so far

| Topic | Decision |
|---|---|
| Name | **Chotam** (חוֹתָם, "seal"). Folder `chotam/`, file magic `CHOTAM` (6 bytes), domain labels `"Chotam v1 …"`. |
| Original filename | Stored **encrypted** in a metadata record inside the stream, not in the plaintext header (FORMAT.md §3). |
| Other spec deviations | See SECURITY.md §6 (D1–D11): HPKE wrap context, domain-separated key IDs, Argon2id limits, fingerprint length, the password rule, Secure Enclave coverage, Keychain entitlement, sandbox and sibling files, two-pass decryption, and bypassing swift-sodium's Swift wrapper. |
| Linux test shim | apple/swift-crypto 5.0.0 + swift-asn1 1.7.3, declared only under `#if os(Linux)`. Never used on macOS. |
| Passphrase wordlist | **Approved by the user (2026-09-30):** the EFF large wordlist (7,776 words, CC-BY 3.0 US), bundled as `EncryptionCore/Sources/EncryptionCore/Resources/eff_large_wordlist.txt`, byte-identical to EFF's file. Its SHA-256 (`addd3553…b903e`) is pinned in code and tests. |
| Argon2id library | **Approved by the user (2026-09-30):** jedisct1/swift-sodium, pinned `exact: "0.11.0"` (tag 0.11.0 = commit `cfd195c76882aa9b997560ca7cb95d72fbf5db00`). Only its `Clibsodium` product (the C library) is used: its Swift wrapper traps on non-ASCII passwords (SECURITY.md D11). On macOS it links the prebuilt static libsodium (`Clibsodium.xcframework`) shipped in that repo; on Linux it needs `libsodium-dev`. |
| Password rule | 14+ characters with an effective length of 14+ (repeats, sequences, years and common words count as one character), **or** 6+ distinct EFF words. Enforced when encrypting, never when decrypting. See SECURITY.md D6. |
| Passphrase generator | 6 distinct EFF words by default (about 77.5 bits), 6–10 allowed, separated by spaces (four EFF words contain hyphens). |
| Where tests run | On the user's Mac: `~/Developer/General-Projects/chotam/EncryptionCore`, `swift test`, Xcode (not the Command Line Tools). The repo must not be on an iCloud-synced folder, or code signing fails. |

## Phase status

| Phase | State |
|---|---|
| 1. FORMAT.md, SECURITY.md, streaming AES-GCM core with key commitment | **Done.** 71 tests pass on macOS. |
| 2. Password mode (Argon2id) | **Written, awaiting `swift test` on macOS.** Not compiled yet: the cloud container has no Swift toolchain. |
| 3. Atomic file processor | Next, after the go-ahead |
| 4–7 | Not started |

---

## Original brief (verbatim)

# Project: Local File Encryption for macOS with Post-Quantum Security (Swift / SwiftUI)

## Motto
Local files. Local encryption. Post-quantum safe. Minimal privileges. No unnecessary system extensions.

## Objective
Build a native, privacy-first macOS app in Swift/SwiftUI that encrypts and decrypts individual local files. It must provide end-to-end post-quantum security for key exchange and sender authentication, and quantum-resistant symmetric encryption.

Two modes:
1. **Password mode** – AES-256-GCM with a key derived from a password using Argon2id. Quantum-resistant as long as the password is strong.
2. **Recipient mode** – a random Data Key per file:
   - wrapped to each recipient with HPKE using the hybrid `XWingMLKEM768X25519_SHA256_AES_GCM_256` ciphersuite;
   - the file is signed by the sender with ML-DSA-65.

There must be **no mode or feature that transmits or exports key material without post-quantum protection.**

## Platform & Constraints
- **Minimum target: macOS 26 (Tahoe), Xcode 26, Swift 6.** Required for CryptoKit's ML-KEM, X-Wing and ML-DSA APIs.
- If any API name, ciphersuite or Secure Enclave capability differs from what I've written, check the actual SDK and **tell me before proceeding**. Never guess or substitute a weaker primitive silently.
- Fully offline. No network, no cloud, no server, no FUSE/macFUSE, no system extensions, no telemetry.
- App Sandbox enabled with only the `user-selected read-write` file entitlement. Enable Hardened Runtime.
- File model: `Document.pdf` → `Document.pdf.enc`, and back.
- **Only allowed dependency: libsodium** (via a well-maintained Swift package), used for Argon2id only. Pin the exact version. No other third-party code without asking me.

## Architecture
- Put all crypto, format and file logic in a **Swift Package** (`EncryptionCore`), testable with `swift test` from the terminal.
- The SwiftUI app is a thin layer. UI code never touches CryptoKit or libsodium directly.
- Keep the crypto API small and hard to misuse. Callers should never handle nonces, salts or raw key bytes.

## Cryptographic Design (follow exactly)

**Symmetric layer**
- AES-256-GCM via CryptoKit, using **streaming, chunked encryption**. Never load a whole file into memory.
- Chunk size: 64 KiB.
- Per-chunk nonce: a random 96-bit base nonce XOR a 64-bit chunk counter.
- The file key is derived from the Data Key (or password key) with HKDF-SHA256 using a fresh random 32-byte per-file salt. Keys are never reused across files.
- AAD for each chunk: header hash + chunk index + final-chunk flag. This detects reordering, truncation and appended data.

**Key commitment**
- Derive a 32-byte commitment tag from the Data Key with HKDF (a separate `info` label from the encryption key) and store it in the header.
- On decrypt, verify it in constant time **before** decrypting any chunk. This prevents one ciphertext from decrypting differently for different recipients.

**Password mode**
- Argon2id via libsodium, at `OPSLIMIT_SENSITIVE` / `MEMLIMIT_SENSITIVE` or the closest parameters with around 1 GiB of memory, plus a 16-byte random salt.
- Store the parameters in the header.
- Enforce a minimum password strength: at least 14 characters or a 6-word passphrase.
- Offer a built-in passphrase generator.

**Recipient mode**
- Generate a random 256-bit Data Key per file.
- Wrap it separately for each recipient with HPKE (X-Wing). Bind the header context as HPKE `info`.
- The header stores each recipient's key ID (SHA-256 of their public key), encapsulated key and wrapped Data Key.

**Sender authentication**
- Every recipient-mode file is signed with the sender's ML-DSA-65 key.
- The signature covers the full header plus a running SHA-256 hash of all ciphertext chunks, and sits in a trailer.
- Decryption verifies the signature **before** releasing any plaintext. Plaintext goes to a temp file and is only moved into place after all chunks and the signature verify.
- The UI must show which trusted contact signed the file, or a clear error if the signer is unknown.

**Identity & key management**
- Each user has an identity made of an X-Wing keypair (encryption) and an ML-DSA-65 keypair (signing).
- Private keys use the Secure Enclave where CryptoKit supports these algorithms. Otherwise they go in the Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and user-presence (Touch ID / password) access control. Tell me which applies.
- Private keys are never exported, logged or written to disk in plaintext.
- Public identities are exported and imported as a `.pqid` file or a copyable Base64 string, containing both public keys.
- **Fingerprint verification:** show a short, human-readable fingerprint (e.g. 8 groups of 4 characters from SHA-256) for every identity.
- Imported contacts start **unverified** until I confirm the fingerprint matches, e.g. by comparing it over a phone call.
- Encrypting to an unverified contact requires an explicit confirmation.

**Hygiene**
- All secret comparisons are constant-time.
- Keep secrets in `SymmetricKey` or equivalent. Minimise copies of raw key bytes, and zero buffers where Swift allows (best effort; document the limits).
- Wrong password, wrong key, bad signature and tampering all fail with one generic message: "Decryption failed: file is damaged or not for you." Details go to debug logs only, and never include secrets.
- Reject unknown format versions, unexpected sizes, recipient counts over 64 and oversized header fields, before doing any expensive work.

## File Format (versioned)
**Header**, used as AAD and signed:
- Magic bytes: `PQENC` *(now `CHOTAM`, see decisions above)*
- Format version: `UInt16` = 1
- Mode: `password` | `recipients`
- Mode parameters:
  - Password: Argon2id salt, opslimit, memlimit
  - Recipients: count, then for each recipient: key ID, encapsulated key, wrapped Data Key
- Sender signing-key ID (recipient mode)
- HKDF salt
- Key commitment tag
- Base nonce
- Chunk size
- Original filename (optional) *(now encrypted inside the stream, see decisions above)*

**Body:** the encrypted chunks.

**Trailer** (recipient mode): the ML-DSA-65 signature.

Document the full format, and a threat model (what this protects against and what it doesn't), in `FORMAT.md` and `SECURITY.md`.

## Safe File Operations
- Write output to a temporary file in the same directory, then atomically replace it into place (`FileManager.replaceItemAt`).
- On any failure, delete the temp file and leave the original untouched.
- Never delete the original automatically; offer it only as an explicit option.
- Warn that secure deletion is not reliable on APFS/SSD. Recommend FileVault.

## UI (SwiftUI)
- Drag-and-drop zone plus a file picker.
- Mode picker: **Password** | **Recipients (Post-Quantum)**.
- Buttons: Encrypt, Decrypt, Create My Identity, Export My Public Identity, Import Contact.
- A contacts list showing fingerprints and verified/unverified status, with a "Mark as verified" action.
- Recipient selection for encryption.
- After decryption, a "Signed by: [contact] ✓ verified" display.
- Progress bar and clear error messages.

## Tests (XCTest)
- Round-trip in both modes: empty file, 1-byte file, exact chunk-boundary file, a file over 100 MB.
- Wrong password, wrong private key, non-recipient.
- Tampering: flipped bit in header, body and trailer; reordered chunks; truncation; appended bytes.
- Signatures: file signed by an unknown key, stripped signature, signature from a different file.
- Key commitment: a crafted header with a mismatched commitment is rejected before decryption.
- Multiple recipients: each can decrypt; outsiders cannot.
- Keychain / Secure Enclave store and load.
- Atomic write: a simulated mid-write failure leaves no partial output and the original intact.
- Malformed input: fuzz the header parser with random and truncated bytes. It must never crash.

## Working Rules
- Work in phases. **Stop after each phase**, show a summary and test results, and wait for my go-ahead.
- Briefly comment every crypto decision in the code.
- If anything in this spec is insecure, ambiguous or impossible with the real APIs, **say so before writing code**. Security beats following my wording.

## Phases
1. `FORMAT.md` + `SECURITY.md` (threat model), then the streaming AES-GCM core with key commitment, with tests
2. Password mode (Argon2id), with tests
3. Atomic file processor, with tests
4. Identities: X-Wing + ML-DSA keys, Keychain / Secure Enclave storage, fingerprints, with tests
5. Recipient mode: HPKE wrapping and signatures, with tests
6. SwiftUI app
7. Full test pass, then a security self-review against `SECURITY.md`, listing any weaknesses honestly
