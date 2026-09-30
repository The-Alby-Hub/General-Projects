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
| Identity private keys (X-Wing, ML-DSA-65) | ML-DSA-65 in the Secure Enclave (Keychain fallback); X-Wing in the Keychain. User presence for every use, this Mac only, never exported (D7) |
| Contact public keys, names and verified status | Keychain items only Chotam can change (D15) |
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
| Quantum attack on the password | Argon2id at about 1 GiB of memory. Grover gives at most a square-root speed-up on a password's entropy, so this holds **only for strong passwords**. The minimum-strength rule (D6) and the generator exist for this reason. A generated 6-word passphrase is about 77.5 bits: classically 2^77 Argon2id runs, and even under Grover about 2^39 *sequential* runs of a 1 GiB memory-hard function inside a quantum computer. | A2 |
| Forged or impersonated sender | ML-DSA-65 signature over the header and all ciphertext, checked against a **verified** contact. | A3, A6 |
| Bit flips, splicing, reordering, truncation, appended data | Per-chunk GCM tags with AAD = header hash, index and final flag (FORMAT §5.3), plus the signature in recipient mode. | A3 |
| One ciphertext decrypting differently for different recipients | Key-commitment tag, checked before any chunk is opened (FORMAT §4.2), plus the signature. | A4 |
| Parser crashes and resource exhaustion | Strict bounded parser. The prelude is checked before any allocation, then sizes, then counts ≤ 64, then Argon2id limits, **before** any key derivation (FORMAT §7). Fuzz-tested. | A4 |
| Moving a wrapped key into another file | HPKE `info` = wrap context; HPKE AAD = recipient key ID (FORMAT §6.2). | A3, A4 |
| Re-targeting a signed file to new recipients | The signature covers the header, including every stanza. | A5 |
| Error messages as an oracle | One generic error for every failure that depends on the file's contents or the key. Only file-system and memory problems, which reveal neither, are reported separately (D13). Details go only to the debug log, as fixed strings. | A3, A4 |
| Trusting the wrong key | 160-bit fingerprints over both public keys (D5). Imported contacts start unverified. Encrypting to an unverified contact needs an explicit confirmation the API can't skip (D16). | A6 |
| An identity pairing someone else's signing key with the attacker's encryption key | Every `.pqid` is self-signed by its ML-DSA-65 key (D14). Two contacts, or a contact and you, can never share a key. | A6 |
| Hostile `.pqid` files or strings | Strict bounded parser: size cap first, exact lengths, name rules, ML-KEM modulus check, then the signature (FORMAT §9.4). Fuzz-tested. | A4, A6 |
| Theft of private keys from disk or backups | The signing key lives in the Secure Enclave where possible. Keychain items are `WhenUnlockedThisDeviceOnly`, never synced or restored to another Mac, and need user presence to read (D7). | A1 |
| Half-written or corrupted outputs | Temp file, flushed to disk, then an atomic exclusive rename or replace. On any failure the temp file is deleted and the destination, including any file already there, is untouched. The original is never modified or deleted (D9). | — |
| A hostile restored filename (`../x`, `.zshrc`, a name that looks like a path) | The name is never used as a path, never replaces a file, and must pass strict rules before it names anything (D12). | A4 |

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
13. **Password-mode files need about 1 GiB of free memory to open.** If Argon2id can't
    allocate it, opening fails with "not enough memory" (D13): the memory cost is public
    header data, and it fails before anything is authenticated. Encrypting needs the same.
14. **A crash can leave a temp file behind.** If the app is killed or the Mac loses power
    mid-operation, the temp file stays in the system's `TemporaryItems` folder (or, as a
    fallback, as a hidden `.chotam-<UUID>.tmp` beside the output). After a decryption,
    that file holds plaintext, some of it possibly not yet authenticated. Only FileVault
    protects it. The app may sweep leftovers at the next launch (Phase 6).
15. **The restored filename is chosen by whoever made the file.** Even when it passes
    D12's rules, it can carry any extension, e.g. `.command` or `.app`. (So can the
    `.enc` file's own name.) The app should mark decrypted outputs as quarantined
    (Phase 6).
16. **Fingerprints resist collisions only to about 2^80, classically.** A second preimage
    (matching someone else's fingerprint) costs about 2^160, or 2^80 with Grover. But a
    person could make **two identities of their own** with the same fingerprint for about
    2^80 work: expensive, but within reach of a very large attacker. That gains them little
    (both identities are theirs). Chotam never uses the fingerprint to tell contacts apart;
    it uses the full 256-bit key IDs.
17. **The X-Wing private key is in memory while a file is opened.** The Secure Enclave
    doesn't support X-Wing, so the key is read from the Keychain (after Touch ID or the
    password) into Chotam's memory for the operation, then dropped. The same holds for the
    ML-DSA-65 key on a Mac where the Secure Enclave couldn't create it (D7). Only the
    Secure Enclave keeps a key out of Chotam's memory entirely.
18. **Identities are tied to one Mac.** Private keys can't be exported, backed up or
    synced (by design). A lost, wiped or replaced Mac means a new identity: contacts must
    import and verify it again, and files encrypted to the old one can't be opened.
19. **Names are self-asserted.** The name in a `.pqid` is chosen by its maker and isn't
    evidence of anything. Only the fingerprint, compared over a channel the user trusts,
    ties an identity to a person.
20. **"Verified" is only as good as the comparison.** Chotam records that the user said
    the fingerprints matched. It can't check how carefully they compared them.

## 6. Design notes and deviations from the original spec

Each of these was flagged before any code was written.

| # | Topic | Decision |
|---|---|---|
| D1 | **Filename in the header** | The spec put it in the plaintext header, which leaks the name. It now goes in an encrypted metadata record (FORMAT §3). |
| D2 | **HPKE `info` was circular** | The header can't bind its own wrapped keys, so `info` is a defined "wrap context" hash (FORMAT §6.2). |
| D3 | **Key IDs** | Domain-separated SHA-256 of the raw public key, so encryption and signing IDs can never collide (FORMAT §6.1). |
| D4 | **Argon2id parameters from a file are attacker-controlled** | Hard ranges are enforced before running Argon2id (FORMAT §2.3). |
| D5 | **Fingerprint length and contents** | 8 groups of 4 **hex** characters is only 128 bits: a quantum second-preimage search (Grover) costs about 2^64. **Approved by the user (2026-09-30):** 8 groups of 4 **Crockford base32** characters = 160 bits (5 bits per character; about 2^80 under Grover), at the same visible length. **Defined in Phase 4 (FORMAT §9.3):** the first 20 bytes of `SHA-256("Chotam v1 identity fingerprint" ‖ X-Wing public key ‖ ML-DSA-65 public key)`, in Crockford base32 (`0-9 A-Z` without I, L, O, U). It covers **both** keys, because the user trusts both: one to encrypt to the contact, one to check their signatures; covering only one would let the other be swapped unnoticed. It covers **nothing else**, so a rename or a new self-signature never changes it. The label keeps fingerprints apart from key IDs and from any future version. Users compare all 8 groups aloud (numbered in the UI); a typed fingerprint is compared the Crockford way (case, spaces, hyphens, O/0 and I/L/1 don't matter), always all 32 symbols. Its collision limit is in §5.16. |
| D6 | **"≥ 14 characters" accepts `aaaaaaaaaaaaaa`** | Decided in Phase 2 (`PasswordPolicy`). A password is accepted if it is **6 or more distinct EFF words**, or it has **14 or more characters and an effective length of 14 or more**. In the effective length, each of these counts as one character: a run of 3+ identical characters, an ascending/descending or keyboard-row run of 3+, an immediate repeat of the preceding 2+ characters, a year 1900–2099, and a common word from a hand-written list of about 120 entries (also matched after undoing `p@ssw0rd`-style substitutions). This is a floor against obvious mistakes, not an entropy estimate. It is enforced inside the encrypt function, not only in the UI, and never on decryption. The generator uses the approved EFF large wordlist: 6 distinct words by default, drawn from the CSPRNG with rejection sampling (no modulo bias). |
| D7 | **Secure Enclave coverage** | **Confirmed in Phase 4** against Apple's CryptoKit documentation for macOS 26: `SecureEnclave` offers `P256`, `MLKEM768`, `MLKEM1024`, `MLDSA65` and `MLDSA87`, and **no X-Wing or X25519**. So: **ML-DSA-65 → Secure Enclave** (`SecureEnclave.MLDSA65.PrivateKey(accessControl:)` with `WhenUnlockedThisDeviceOnly` and `[.privateKeyUsage, .userPresence]`: every signature needs Touch ID or the password, **chosen by the user 2026-09-30**). Its `dataRepresentation`, a handle only this Mac's Secure Enclave can use, is kept in the Keychain. **X-Wing → Keychain**: its `integrityCheckedRepresentation` (seed ‖ SHA3-256 of the public key) in a generic-password item, `WhenUnlockedThisDeviceOnly` + `.userPresence`, data-protection keychain, not synchronizable. **Fallback, chosen by the user 2026-09-30:** if this Mac's Secure Enclave can't create the ML-DSA-65 key (no Secure Enclave, a virtual machine, older hardware), it goes in the Keychain exactly like the X-Wing key. This is decided once, at creation, and shown to the user (`Identity.signingKeyStorage`); a cancelled prompt or any other error never triggers it. On the user's iMac (2026-09-30) the real Secure Enclave created an ML-DSA-65 key, signed with it and reopened it from its handle under `swift test` (without user presence, so no prompt), so that Mac uses the Secure Enclave path. Rejected alternative: keeping X-Wing's ML-KEM half in the Secure Enclave and combining it with X25519 ourselves would mean re-implementing X-Wing and HPKE. Private keys are never exported, logged or written anywhere else; the key bytes pass through memory only while stored, or loaded for one operation, and our copies are wiped (best effort, §7.3). |
| D8 | **Keychain entitlement and testing** | The data-protection keychain needs a signed app with a `keychain-access-groups` entitlement, in addition to `user-selected read-write`, so `swift test` can't use it. **Decided in Phase 4:** all identity and contact logic is written against two small internal protocols: `SecureItemStore` (add, replace, copy, delete, list, with a protection level per item) and `SecureEnclaveSigning` (create or reopen an ML-DSA-65 key). Production uses `KeychainItemStore` and `SystemSecureEnclave`; unit tests use an in-memory store that records each item's protection, and a fake Secure Enclave that can be "unavailable" or "cancelled". **Tested under `swift test`:** key generation and sizes on the real SDK, key IDs, fingerprints, `.pqid` parsing and fuzzing, creating, loading and deleting an identity, where each key lands and with what protection, the fallback, clean-up after failures, contacts, and recipient confirmation. On macOS also the exact Keychain query attributes, and (skipped if unsupported) an ML-DSA-65 key in the real Secure Enclave without user presence. **Not tested until the app-hosted Xcode target (Phase 6):** real Keychain add, read, replace and delete with the access group; the accessibility and access control read back from stored items; that a protected read with UI disallowed fails; the Secure Enclave create → store → reopen → sign cycle with user presence; the fallback on a Mac without it; which error a cancelled prompt really produces; persistence across relaunches; and how many prompts each operation shows. |
| D9 | **Sandbox and sibling files** | `user-selected read-write` grants access to the chosen file, not its folder, so `Document.pdf.enc` can't be created beside it without more. **Decided in Phase 3.** The core never assumes it may write beside the input. Callers pass a `Destination`: an exact file (from an NSSavePanel prefilled with `FileProcessor.encryptedName(for:)`) or a folder the user granted. Security-scoped access stays in the app. **Temp file:** in a private folder from `FileManager.url(for: .itemReplacementDirectory, appropriateFor: destination folder)`, on the destination's volume. If the system can't provide one, it falls back to a hidden `.chotam-<UUID>.tmp` in the destination folder; if neither works, the operation fails with an I/O error. It is created only on the first write, with `O_EXCL` and mode 0600 (the output keeps 0600). It is flushed with `F_FULLFSYNC` (else `fsync`) before it is moved. **New output:** an exclusive rename (`renamex_np(RENAME_EXCL)`, or `link` + `unlink` where that's unsupported). It fails atomically if anything appeared at the name, with no check-then-rename race. There is no cross-volume copy fallback, because a copy isn't atomic. **Existing output:** refused with `outputExists` before any work, unless the caller passes `replacingExisting: true` (the user confirmed in the save panel). It is then replaced with `replaceItemAt(…, options: .usingNewMetadataOnly)`, so the old file's tags, quarantine flag or download origin don't carry over. The destination can't be the input itself (same device and inode), a folder or a symbolic link. **Failure:** the temp file and its private folder are deleted, and the destination is exactly as before. Whether `.itemReplacementDirectory` works for a sandboxed app on external volumes is confirmed in Phase 6 on a signed build; `swift test` can't check it. |
| D10 | **Unverified plaintext on disk** | Proposal for Phase 5: pass 1 verifies the signature over the ciphertext only; pass 2 decrypts to a temp file and checks the ciphertext hash hasn't changed. Plaintext of a forged file is then never written. Some plaintext still touches the temp file before the final chunk is checked (see 5.4). |
| D11 | **swift-sodium's Swift wrapper is not used** | In swift-sodium 0.11.0, `PWHash.hash` converts every password byte with `Int8.init`, which traps on any byte ≥ 0x80: every non-ASCII password (Hebrew, accented letters, emoji) would crash the app. It also copies the password into an array that can't be wiped. Chotam depends only on the package's `Clibsodium` product and calls `crypto_pwhash` directly, with the password in a buffer it allocates and wipes. A regression test derives keys from Hebrew and emoji passwords. |
| D12 | **The restored filename is attacker-chosen** | The name stored inside a file (FORMAT §3) comes from its author. Decided in Phase 3. It is used **only** to name a new file inside a `Destination.folder`, and only if it passes the decoder's rules (no `/`, control or bidirectional characters, not `.`/`..`) **and** doesn't start with `.` (no planting `.zshrc` or `.lldbinit`), doesn't contain `:` (Finder shows it as `/`), and is at most 255 bytes. Otherwise the `.enc` file's own name without `.enc` is used, and failing that, `Decrypted file`. The final URL is checked to be exactly one component inside the chosen folder. On a name clash it tries `Report 2.pdf`, `Report 3.pdf`, … (up to 100) with an exclusive rename, so it never replaces anything, and case-insensitive or normalising file systems are handled by the file system itself. With `Destination.file` the name is ignored and only returned in `DecryptedFile.storedFilename`, for display as text. |
| D13 | **Public errors** | Decided in Phase 3; the split was chosen by the user. Decryption keeps **one generic error**, `DecryptionError.failed`, for everything that depends on the file's bytes or the password: wrong password, tampering, truncation, malformed or wrong-mode files. Failures that reveal neither are reported as they are: `notEnoughMemory` (Argon2id's cost is public header data and fails before any authentication), and `file(FileProblem)`: the input isn't a file, the output exists, an invalid destination, access denied, a read or write failure. A write failure can only happen after chunk 0 authenticated, so in principle it tells the user their password was right; it tells an attacker without access to the user's screen nothing. Encryption works on the user's own file and can't be an oracle, so its errors are precise: `weakPassword`, `invalidFilename`, `notEnoughMemory`, `file(FileProblem)`, `unexpected`. Messages are fixed strings and never include paths. |
| D14 | **Self-signed public identities** | Decided in Phase 4 (approved by the user 2026-09-30). Every `.pqid` carries an ML-DSA-65 signature by its own signing key over everything else in it (FORMAT §9.2). Without it, Mallory could publish an identity with **Alice's signing key** and his own encryption key; after verifying *that* fingerprint with Mallory, Bob would see Alice's signed files as "Signed by: Mallory ✓". With it, Mallory would need Alice's private key. The opposite pairing (Mallory's signing key with **Bob's** encryption key) only sends Mallory's mail to Bob, but Chotam refuses it too: no two contacts, and no contact and your own identity, may share a key. The signature is made once, at creation (one prompt), so exporting never prompts. It proves possession of the signing key, not who holds it; that is what fingerprints are for. |
| D15 | **Where contacts live** | Decided in Phase 4 (chosen by the user 2026-09-30): in the Keychain, one generic-password item per contact (service `app.chotam.contacts`, account = hex encryption-key ID), `WhenUnlockedThisDeviceOnly`, not synchronizable, no prompt (public data). Keychain items are protected by the app's code signature, so no other program can flip a "verified" flag or swap a contact's key, as it could in a file in the app's container. The cost: contacts aren't in backups and don't move to another Mac, like the identity itself. Records are parsed strictly and their `.pqid` re-verified on every load (FORMAT §10). |
| D16 | **Encrypting to unverified contacts** | Decided in Phase 4. Recipients are passed as a `RecipientList`. `RecipientList(contacts)` throws `.needsConfirmation(request)` if any contact is unverified; the request lists exactly those contacts, and `request.confirm()` is the only way to build a list that includes them. There is no Boolean flag or default argument that skips it. The core can't prove a human saw the dialog, so the app must call `confirm()` only from the user's "Encrypt anyway" action. |

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
    wiped. Neither can the NFC-normalised copy of the password. The UTF-8 bytes handed to
    libsodium sit in a buffer Chotam allocates and wipes after use. libsodium wipes its own
    Argon2id working memory.
  - The OS may page memory to swap. macOS encrypts swap, and FileVault covers the disk.

### 7.4 Errors and logging
- Every decryption failure that depends on the file's contents or the key maps to the
  single public message. File-system and memory problems are reported separately (D13).
- Detailed reasons are fixed enum strings, logged at debug level via `os.Logger`, and
  never include key material, passwords, plaintext or filenames.

### 7.5 Dependencies
- Apple CryptoKit (system framework).
- libsodium for Argon2id only, via jedisct1/swift-sodium pinned `exact: "0.11.0"`
  (commit `cfd195c76882aa9b997560ca7cb95d72fbf5db00`). Only the `Clibsodium` product is
  linked (D11). On Apple platforms it is a **prebuilt static libsodium** shipped in that
  repository (`Clibsodium.xcframework`). We didn't build it ourselves, so we trust its
  publisher: swift-sodium is maintained by libsodium's author. The exact pin plus the
  commit recorded in `Package.resolved` stops it changing silently. On Linux the system
  `libsodium-dev` is used instead.
- The EFF large wordlist (CC-BY 3.0 US, Electronic Frontier Foundation), bundled as data
  and checked against a pinned SHA-256 before use.
- apple/swift-crypto and swift-asn1 are declared **only when building on Linux**, so the
  core can be tested in a Linux container. They are not declared, fetched or linked on
  macOS. swift-crypto 5.0.0 includes `MLDSA65`, `XWingMLKEM768X25519` and the X-Wing HPKE
  ciphersuite (BoringSSL-backed), so identities and recipient mode build and test on
  Linux too. It has no Secure Enclave or Keychain: those two backends are compiled only
  on Apple platforms, and `IdentityStore.system` doesn't exist on Linux.
- The identity test vector was generated with kyber-py, dilithium-py and
  pyca/cryptography (test-time tools, not dependencies of Chotam).
