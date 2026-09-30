# Chotam: project specification

This is the original project brief, kept verbatim below so any new session can
work from it. **Decisions made since then override the brief where they differ.**
They're listed first.

## Decisions and deviations so far

| Topic | Decision |
|---|---|
| Name | **Chotam** (חוֹתָם, "seal"). Folder `chotam/`, file magic `CHOTAM` (6 bytes), domain labels `"Chotam v1 …"`. |
| Original filename | Stored **encrypted** in a metadata record inside the stream, not in the plaintext header (FORMAT.md §3). |
| Other spec deviations | See SECURITY.md §6 (D1–D16): HPKE wrap context, domain-separated key IDs, Argon2id limits, fingerprint length and contents, the password rule, Secure Enclave coverage, Keychain entitlement and testing, sandbox and sibling files, two-pass decryption, bypassing swift-sodium's Swift wrapper, the restored filename, the public errors, self-signed identities, where contacts live, and confirming unverified recipients. |
| Linux test shim | apple/swift-crypto 5.0.0 + swift-asn1 1.7.3, declared only under `#if os(Linux)`. Never used on macOS. |
| Passphrase wordlist | **Approved by the user (2026-09-30):** the EFF large wordlist (7,776 words, CC-BY 3.0 US), bundled as `EncryptionCore/Sources/EncryptionCore/Resources/eff_large_wordlist.txt`, byte-identical to EFF's file. Its SHA-256 (`addd3553…b903e`) is pinned in code and tests. |
| Argon2id library | **Approved by the user (2026-09-30):** jedisct1/swift-sodium, pinned `exact: "0.11.0"` (tag 0.11.0 = commit `cfd195c76882aa9b997560ca7cb95d72fbf5db00`). Only its `Clibsodium` product (the C library) is used: its Swift wrapper traps on non-ASCII passwords (SECURITY.md D11). On macOS it links the prebuilt static libsodium (`Clibsodium.xcframework`) shipped in that repo; on Linux it needs `libsodium-dev`. |
| Password rule | 14+ characters with an effective length of 14+ (repeats, sequences, years and common words count as one character), **or** 6+ distinct EFF words. Enforced when encrypting, never when decrypting. See SECURITY.md D6. |
| Passphrase generator | 6 distinct EFF words by default (about 77.5 bits), 6–10 allowed, separated by spaces (four EFF words contain hyphens). |
| File API (Phase 3) | `FileProcessor.encrypt(_:to:using:)` / `decrypt(_:to:using:)`. Callers pass URLs, a `Destination` (`.file(url, replacingExisting:)` or `.folder(url)`) and a mode (`.password(…)`), never streams, salts or keys. Modes are opaque structs with static factories, so recipient mode (Phase 5) is added without changing the shape. Synchronous: the app calls it off the main thread. |
| Safe writes and the sandbox (D9) | The temp file goes in a private `.itemReplacementDirectory` folder on the destination's volume (fallback: a hidden `.chotam-<UUID>.tmp` in the destination folder). It is created lazily (a wrong or weak password creates nothing), mode 0600, and flushed with `F_FULLFSYNC`. A new output is moved in with an exclusive rename (`renamex_np(RENAME_EXCL)`), so nothing is ever overwritten by accident. An existing output is replaced (`replaceItemAt`) only with `replacingExisting: true`, i.e. after the user confirmed it. On any failure the temp file is deleted and the destination is untouched. The original is never modified or deleted. See SECURITY.md D9. |
| Public errors (D13) | Encryption: `weakPassword`, `invalidFilename`, `notEnoughMemory`, `file(FileProblem)`, `unexpected`. Decryption: **`failed` (the one generic message)** for anything about the contents or the password, plus `notEnoughMemory` and `file(FileProblem)`, which reveal nothing about either. **Chosen by the user (2026-09-30).** `FileProblem`: `inputNotAFile`, `outputExists`, `invalidDestination`, `accessDenied`, `readFailed`, `writeFailed`. |
| Restored filename (D12) | Used only to name a new file inside a `.folder` destination, and only if it's safe (no leading `.`, no `:`, ≤ 255 bytes, on top of FORMAT.md §3's rules); otherwise the `.enc` name without `.enc` is used. It never replaces a file (`Report 2.pdf`, …) and is never treated as a path. With a `.file` destination it's only returned for display. |
| Output permissions | Outputs (encrypted and decrypted) are created owner-only, mode 0600. |
| Fingerprint format (D5) | **Approved by the user (2026-09-30):** 8 groups of 4 Crockford base32 characters = 160 bits (about 2^80 against a quantum second-preimage search), instead of the brief's 128-bit hex. **Bytes hashed (Phase 4):** the first 20 bytes of `SHA-256("Chotam v1 identity fingerprint" ‖ X-Wing public key ‖ ML-DSA-65 public key)`: both keys, nothing else (FORMAT.md §9.3). Compared by reading all 8 groups aloud; typed input is normalised the Crockford way (O→0, I/L→1, case, spaces and hyphens ignored). |
| CryptoKit names (checked 2026-09-30) | As in the brief: `XWingMLKEM768X25519`, `MLDSA65`, `SecureEnclave.MLDSA65`, `HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256`. `SecureEnclave` also has `MLKEM768`/`MLKEM1024`/`MLDSA87`/`P256` but **no X-Wing**. All sizes FORMAT.md relies on (X-Wing 1216 / 1120, ML-DSA-65 1952 / 3309, wrapped Data Key 48) are confirmed on the SDK by tests that passed on macOS (2026-09-30). |
| Key placement (D7) | **ML-DSA-65 in the Secure Enclave**, with user presence for every signature (chosen by the user 2026-09-30). **X-Wing in the Keychain** (`WhenUnlockedThisDeviceOnly` + user presence), because the Secure Enclave has no X-Wing. **If the Secure Enclave can't create the ML-DSA-65 key**, it goes in the Keychain the same way (chosen by the user 2026-09-30), decided once at creation and shown in the UI. |
| Public identity (`.pqid`, D14) | Versioned binary: `CHOTAMID`, both public keys, an optional suggested name (≤ 64 bytes), and a **self-signature** by the identity's ML-DSA-65 key (approved by the user 2026-09-30). 6,494–6,558 bytes; the copyable string is standard Base64 of the same bytes. Strict, bounded, fuzz-tested parser (FORMAT.md §9). |
| Contacts (D15, D16) | Stored in the **Keychain** (chosen by the user 2026-09-30), one item per contact. Imports start unverified; "Mark as verified" after comparing fingerprints. No two contacts (or a contact and you) may share a key. Recipients are passed as a `RecipientList`, which can only include unverified contacts through `request.confirm()` after the user confirms. |
| Identity API (Phase 4) | `IdentityStore.system`: `myIdentity()`, `createIdentity(name:)`, `deleteMyIdentity()`, `contacts()`, `importContact(_:name:)`, `markVerified(_:)`, `rename(_:to:)`, `remove(_:)`. `PublicIdentity(importing:)` / `(importingString:)`, `exportedData` / `exportedString`, `fingerprint`. Errors: `IdentityError`. Phase 5 adds `EncryptionMode.recipients(_:signedBy:)` and a decryption mode that takes your `Identity`; nothing here changes. |
| Linux and identities | swift-crypto 5.0.0 has `MLDSA65`, `XWingMLKEM768X25519` and the X-Wing HPKE ciphersuite, so Phases 4–5 build and test on Linux. Only the Keychain and Secure Enclave backends (and `IdentityStore.system`) are Apple-only. |
| Where tests run | On the user's Mac: `~/Developer/General-Projects/chotam/EncryptionCore`, `swift test`, Xcode (not the Command Line Tools). The repo must not be on an iCloud-synced folder, or code signing fails. |

## Phase status

| Phase | State |
|---|---|
| 1. FORMAT.md, SECURITY.md, streaming AES-GCM core with key commitment | **Done.** 71 tests pass on macOS. |
| 2. Password mode (Argon2id) | **Done.** 113 tests pass on macOS (2026-09-30). `Package.resolved` pins swift-sodium at `cfd195c7…`; the bundled wordlist matches eff.org's SHA-256. |
| 3. Atomic file processor | **Done.** 138 tests pass on macOS (2026-09-30), 25 of them new: public `FileProcessor` API, safe writes, restored-filename rules, public errors. |
| 4. Identities | **Done.** 222 tests pass on macOS (2026-09-30), 84 of them new: keys and SDK sizes, key IDs, fingerprints, `.pqid` (golden file, strict parser, fuzzing), identity storage through fakes, contacts, recipient confirmation, Keychain query attributes. The real Secure Enclave created and used an ML-DSA-65 key on the user's iMac (test not skipped). PR [#10](https://github.com/The-Alby-Hub/General-Projects/pull/10). |
| 5–7 | Not started |

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
