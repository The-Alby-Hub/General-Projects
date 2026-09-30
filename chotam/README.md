# Chotam (חוֹתָם): local, post-quantum file encryption for macOS

*Chotam* is Hebrew for "seal", as in a signet seal pressed into wax: it keeps a document closed and proves who sealed it.

**Local files. Local encryption. Post-quantum safe. Minimal privileges. No unnecessary system extensions.**

A native macOS 26 (Swift 6 / SwiftUI) app that encrypts individual files:

- **Password mode:** Argon2id → HKDF → streaming AES-256-GCM.
- **Recipient mode:** a per-file Data Key, wrapped with HPKE X-Wing (ML-KEM-768 + X25519)
  and signed with ML-DSA-65.

| Document | Contents |
|---|---|
| [FORMAT.md](FORMAT.md) | Byte-level file format v1 |
| [SECURITY.md](SECURITY.md) | Threat model, non-goals, known limits, deviations from the spec |
| [SPEC.md](SPEC.md) | The original brief, plus every decision made since |

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | FORMAT.md, SECURITY.md, streaming AES-GCM core with key commitment | done: 71 tests pass on macOS (Xcode) |
| 2 | Password mode (Argon2id via libsodium), password rule, passphrase generator | done: 113 tests pass on macOS (Xcode) |
| 3 | Atomic file processor: public `FileProcessor` API, safe writes, restored filenames | done: 138 tests pass on macOS (Xcode) |
| 4 | Identities, Keychain / Secure Enclave, fingerprints, `.pqid`, contacts | code complete, 84 new tests (222 in all); awaiting a run on macOS |
| 5 | Recipient mode: HPKE wrapping, ML-DSA signatures | — |
| 6 | SwiftUI app | — |
| 7 | Full test pass and security self-review | — |

## Layout

```
chotam/
  FORMAT.md, SECURITY.md
  EncryptionCore/                Swift package: all crypto, format and file logic
    Sources/EncryptionCore/
      Errors.swift               single public error; internal reasons → debug log
      Format/                    v1 constants, header model, strict codec, byte reader/writer
      Crypto/                    HKDF key schedule + commitment, nonces/AAD, constant-time, wiping
      Stream/                    chunked sealer/opener, byte sources/sinks, metadata record
      Password/                  Argon2id (libsodium), password mode, strength rule, passphrase generator
      Files/                     public file API: FileProcessor, safe temp-file writes, output naming, public errors
      Identity/                  identities, key IDs, fingerprints, .pqid codec, contacts, recipient lists
        Storage/                 Keychain and Secure Enclave backends behind small protocols (SECURITY.md D8)
      Resources/                 EFF large wordlist (CC-BY 3.0 US)
    Tests/EncryptionCoreTests/   XCTest
      Vectors/                   golden .enc and .pqid files from independent implementations (FORMAT.md §8, §9.5)
```

## Using the core

The public API works on files. Callers never handle streams, salts, nonces or keys.

```swift
import EncryptionCore

// Encrypt: Document.pdf → Document.pdf.enc in a folder the user granted
// (or pass .file(url) from a save panel prefilled with FileProcessor.encryptedName(for:)).
let encrypted = try FileProcessor.encrypt(
    documentURL, to: .folder(folderURL), using: .password(password))

// Decrypt: into a folder, named after the filename stored inside the file.
let result = try FileProcessor.decrypt(
    encrypted, to: .folder(folderURL), using: .password(password))
result.url             // where the plaintext was saved, e.g. Document.pdf (or "Document 2.pdf")
result.storedFilename  // the original name, for display only
```

- Both calls are slow on purpose (Argon2id: about a second and 1 GiB), so run them off
  the main thread.
- The result is written to a temp file and moved into place atomically, only once it
  is complete (for decryption, only once every chunk has authenticated). On any failure
  nothing is left behind, and an existing file is never overwritten unless you pass
  `.file(url, replacingExisting: true)`.
- The original is never modified or deleted.
- Errors are `EncryptionError` and `DecryptionError`. Every problem with an encrypted
  file's contents, or a wrong password, is the single
  `DecryptionError.failed`: "Decryption failed: file is damaged or not for you."
  See [SECURITY.md](SECURITY.md) D9, D12 and D13.

## Identities and contacts

Recipient mode (Phase 5) encrypts to contacts and signs with your identity. Phase 4 adds
the identities themselves:

```swift
let store = IdentityStore.system   // the Keychain and Secure Enclave; needs the signed app

// Once: create your identity (one Touch ID / password prompt, to sign your .pqid).
let me = try store.myIdentity() ?? store.createIdentity(name: "Alice")
me.fingerprint.description         // "P6BC HMEY 9SAS BEA0 DGKS 1Y3H FDP9 VXBM"
me.publicIdentity.exportedData     // save as Alice.pqid
me.publicIdentity.exportedString   // or copy this Base64 string
me.signingKeyStorage               // .secureEnclave (or .keychain on a Mac whose SE can't)

// Import a contact: always unverified.
let bob = try store.importContact(PublicIdentity(importing: pqidData), name: "Bob")
bob.fingerprint                    // read all 8 groups aloud with Bob, then:
let verified = try store.markVerified(bob)

// Choosing recipients: unverified contacts need an explicit confirmation.
let recipients: RecipientList
do {
    recipients = try RecipientList(selectedContacts)
} catch let error as RecipientSelectionError {
    // Name request.unverifiedContacts in a dialog; continue only if the user confirms.
    guard case .needsConfirmation(let request) = error, userConfirmed(request.unverifiedContacts) else { return }
    recipients = request.confirm()
}
```

- Private keys never leave the Mac and are never exported. ML-DSA-65 lives in the Secure
  Enclave; X-Wing lives in the Keychain, because the Secure Enclave has no X-Wing. Both
  need Touch ID or the password for every use. See SECURITY.md D7.
- A `.pqid` holds both public keys, an optional suggested name and a self-signature
  (FORMAT.md §9). Anyone can make one, so an identity means nothing until its
  fingerprint has been compared.
- Errors are `IdentityError` (and `RecipientSelectionError` for recipient lists).

## Building and testing

**macOS 26 with Xcode 26** (authoritative):

```sh
cd chotam/EncryptionCore
swift test
```

This uses the system CryptoKit. The first run fetches one package,
[jedisct1/swift-sodium](https://github.com/jedisct1/swift-sodium) 0.11.0, pinned exactly. Only
its `Clibsodium` product (libsodium itself) is linked, for Argon2id. `Package.resolved`
should show revision `cfd195c76882aa9b997560ca7cb95d72fbf5db00`.

Identity and contact tests run on an in-memory store and a fake Secure Enclave, because
the real Keychain needs a signed app with the `keychain-access-groups` entitlement
(SECURITY.md D8). On macOS, one test also tries an ML-DSA-65 key in the real Secure
Enclave (without a prompt) and is skipped if this Mac can't do it.

Password-mode tests run Argon2id for real. Most use the cheapest cost a file may declare
(ops 3, 256 MiB). A few use the production preset (ops 4, 1 GiB) and take several
seconds each.

**Linux** (development convenience only). Needs a Swift 6.2 toolchain. The manifest then adds
[apple/swift-crypto](https://github.com/apple/swift-crypto) 5.0.0 and swift-asn1 1.7.3,
both pinned exactly. They provide the same `AES.GCM` / `HKDF` / `SHA256` / `SymmetricKey`
API, and also `MLDSA65`, `XWingMLKEM768X25519` and the X-Wing HPKE ciphersuite, so the
identity code builds and tests on Linux as well (without the Keychain and Secure Enclave
backends, which are Apple-only). They are declared inside `#if os(Linux)`, so a macOS build never resolves them.
libsodium comes from the system: `apt install libsodium-dev`.

```sh
cd chotam/EncryptionCore
swift build && swift test
```

## Credits

The passphrase generator uses the [EFF large wordlist](https://www.eff.org/dice) by the
Electronic Frontier Foundation, licensed under
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/). It is bundled unmodified.
