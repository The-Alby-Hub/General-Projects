# Chotam (חוֹתָם): local, post-quantum file encryption for macOS

*Chotam* is Hebrew for "seal", as in a signet seal pressed into wax: it keeps a document closed and proves who sealed it.

**Local files. Local encryption. Post-quantum safe. Minimal privileges. No unnecessary system extensions.**

A native macOS 26 (Swift 6 / SwiftUI) app that encrypts individual files:

- **Password mode:** Argon2id → HKDF → streaming AES-256-GCM.
- **Recipient mode:** a per-file Data Key, wrapped with HPKE X-Wing (ML-KEM-768 + X25519)
  and signed with a hybrid Ed25519 + ML-DSA-65 signature.
- **Identities are derived from a generated passphrase.** No secret is ever stored, and
  Chotam never uses the Keychain (SECURITY.md D17, D18).

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
| 4 | Identities, fingerprints, `.pqid`, contacts | done: 222 tests pass on macOS (Xcode); its Keychain parts removed in 5a |
| 5a | Passphrase-derived identity, no Keychain, hybrid signatures, encrypted contacts | done: 238 tests pass on macOS (Xcode); unlock takes 3.5 s |
| 5b | Recipient mode: HPKE wrapping, signed files, two-pass decryption, cancellation with cleanup | done: 273 tests pass on macOS (Xcode); CryptoKit opens the independent golden files |
| 6a | App: project, identity, contacts, automatic locking, public progress/cancel API | written; awaiting the first build and run on macOS |
| 6b | App: encrypt/decrypt, recipients, progress bar, quarantine, temp sweep | — |
| 7 | Full test pass and security self-review | — |

## Layout

```
chotam/
  FORMAT.md, SECURITY.md, SPEC.md
  App/                           the macOS app (SwiftUI + AppKit glue only)
    Chotam.xcodeproj             hand-written, file-system-synchronized folders (SECURITY.md D27)
    Chotam/                      views, the secure passphrase field, panels, lock events, launch hardening
    Config/                      Info.plist and Chotam.entitlements (sandbox + user-selected files only)
  AppModel/                      Swift package ChotamAppModel: view models and app logic, `swift test`-able
  EncryptionCore/                Swift package: all crypto, format and file logic
    Sources/EncryptionCore/
      Errors.swift               single public error; internal reasons → debug log
      Format/                    v1 constants, header model, strict codec, byte reader/writer
      Crypto/                    HKDF key schedule + commitment, nonces/AAD, constant-time, wiping
      Stream/                    chunked sealer/opener, byte sources/sinks, metadata record
      Password/                  Argon2id (libsodium), password mode, strength rule, passphrase generator
      Files/                     public file API: FileProcessor, safe temp-file writes, output naming, public errors
      Identity/                  derived identities, key IDs, fingerprints, hybrid signatures, .pqid codec,
                                 the encrypted contacts file, recipient lists
      Recipient/                 recipient mode: HPKE X-Wing wrapping, file signatures, two-pass decryption
      Resources/                 EFF large wordlist (CC-BY 3.0 US)
    Tests/EncryptionCoreTests/   XCTest
      Vectors/                   golden .enc and .pqid files from independent implementations (FORMAT.md §8, §9.7),
                                 and the Python scripts that make them
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
  the main thread, or use the async versions below.
- The result is written to a temp file and moved into place atomically, only once it
  is complete (for decryption, only once every chunk has authenticated). On any failure
  nothing is left behind, and an existing file is never overwritten unless you pass
  `.file(url, replacingExisting: true)`.
- The original is never modified or deleted.
- Errors are `EncryptionError` and `DecryptionError`. Every problem with an encrypted
  file's contents, or a wrong password, is the single
  `DecryptionError.failed`: "Decryption failed: file is damaged or not for you."
  See [SECURITY.md](SECURITY.md) D9, D12 and D13.

### Progress and cancellation

```swift
// Async versions: progress from 0 to 1, and cancelling the Task cancels the operation.
let task = Task {
    try await FileProcessor.encrypt(documentURL, to: .file(saveURL), using: mode,
                                    progress: { fraction in /* update a progress bar */ })
}
task.cancel()   // → EncryptionError.cancelled; nothing is left behind (SECURITY.md D24, D28)
```

The work runs on its own queue. Cancellation is checked before every read, between the
two passes of a recipient-mode decryption and before the result is moved into place;
Argon2id itself always finishes first. The synchronous API is unchanged.

## Identities and contacts

Recipient mode (Phase 5b) encrypts to contacts and signs with your identity. Your identity
is **derived from a passphrase Chotam generates**. Nothing secret is stored anywhere: not
in the Keychain (Chotam never touches it), not on disk. The keys exist in memory only
while the identity is unlocked.

```swift
// The folder holding identity.pqid (public) and contacts.chotam (encrypted).
let vault = IdentityVault(folder: appSupportFolder)

// Once: create your identity. Show the passphrase once, have it written down, drop it.
let created = try vault.createIdentity(name: "Alice")      // optionally keyFile: url
created.passphrase                  // 7 EFF words, about 90 bits. No recovery if lost.
let me = created.identity

// Later (each launch): unlock. Case and spacing don't matter. A few seconds, ~1 GiB.
let me = try vault.unlock(passphrase: typed)                 // keyFile: if it has one
me.fingerprint.description         // "80XX XYHV TNDW KMXW QJ1J KY3M 0SVB QTVM"
me.publicIdentity.exportedData     // save as Alice.pqid
me.publicIdentity.exportedString   // or copy this Base64 string
me.lock()                           // on quit, screen lock, sleep, idle: wipes the keys

// On a new Mac: your .pqid (e.g. from a contact) plus the passphrase.
let me = try vault.restore(PublicIdentity(importing: myPQID), passphrase: typed)

// Contacts belong to the unlocked identity. Imports are always unverified.
let bob = try me.importContact(PublicIdentity(importing: pqidData), name: "Bob")
bob.fingerprint                    // read all 8 groups aloud with Bob, then:
let verified = try me.markVerified(bob)

// Choosing recipients (at most 63: you are always the 64th). Unverified contacts
// need an explicit confirmation.
let recipients: RecipientList
do {
    recipients = try RecipientList(selectedContacts)
} catch let error as RecipientSelectionError {
    // Name request.unverifiedContacts in a dialog; continue only if the user confirms.
    guard case .needsConfirmation(let request) = error, userConfirmed(request.unverifiedContacts) else { return }
    recipients = request.confirm()
}
```

- **The passphrase is the identity.** Anyone holding your `.pqid` can guess passphrases
  offline, which is why Chotam generates them and refuses chosen ones. A forgotten
  passphrase (or lost key file) can't be recovered, and a new passphrase means a new
  identity. See SECURITY.md D17 and §5.17–§5.25.
- A `.pqid` holds three public keys, the public parameters for re-deriving the identity,
  an optional suggested name and a hybrid self-signature (FORMAT.md §9). Anyone can make
  one, so an identity means nothing until its fingerprint has been compared.
- `forgetThisMac()` removes the two files; it can't delete the identity itself.
- Errors are `IdentityError` (and `RecipientSelectionError` for recipient lists).

## Recipient mode

```swift
// Encrypt to the chosen contacts. You are always added as a recipient, so you can
// open what you sent. The file is signed with your hybrid Ed25519 + ML-DSA-65 key.
let encrypted = try FileProcessor.encrypt(
    documentURL, to: .folder(folderURL), using: .recipients(recipients, signedBy: me))

// Decrypt with your unlocked identity. The file is read twice: the signature is
// checked first, and nothing is written unless it verifies.
let result = try FileProcessor.decrypt(encrypted, to: .folder(folderURL), using: .identity(me))
switch result.signer {
case .you?:                         // "Signed by: you"
case .verifiedContact(let c)?:      // "Signed by: \(c.name) ✓ verified"
case .unverifiedContact(let c)?:    // "Signed by: \(c.name) (not verified)": offer to compare fingerprints
case nil:                           // password mode: no signer
}
```

- Each file gets a fresh random 256-bit Data Key, wrapped to every recipient with HPKE
  (X-Wing: ML-KEM-768 + X25519). At most 63 contacts per file; the 64th stanza is yours.
- A file signed by someone who is neither you nor a contact is refused with
  `DecryptionError.unknownSender`. Every other problem (not for you, a bad signature,
  tampering) is the generic `.failed`.
- `recipients` must come from the signing identity's current contacts, or encryption
  fails with `.recipientsChanged`. A locked identity gives `.identity(.locked)`.
- Cancelling or failing at any point, in either pass, leaves nothing behind: the temp
  file is deleted and keys and buffers are wiped (SECURITY.md D24). Use the async
  versions above for progress and cancellation.

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

Identity and contact tests run for real, in temp folders: there is no Keychain to fake.
Most derive identities at the cheapest accepted cost (ops 3, 256 MiB). One test runs the
production cost once (1 GiB, ops 8) and prints how long it took, for calibration:
look for `Chotam calibration:` in the output. `NoKeychainTests` fails if any source
file ever uses a Keychain, Secure Enclave or Touch ID API.

Recipient-mode tests use real identities in temp folders, plus golden files made by an
independent Python implementation of HPKE and X-Wing (FORMAT.md §8). One test streams a
file over 100 MB through both passes. Cancellation tests stop operations part-way
through each pass and check that nothing is left on disk.

Password-mode tests run Argon2id for real. Most use the cheapest cost a file may declare
(ops 3, 256 MiB). A few use the production preset (ops 4, 1 GiB) and take several
seconds each.

**Linux** (development convenience only). Needs a Swift 6.2 toolchain. The manifest then adds
[apple/swift-crypto](https://github.com/apple/swift-crypto) 5.0.0 and swift-asn1 1.7.3,
both pinned exactly. They provide the same `AES.GCM` / `HKDF` / `SHA256` / `SymmetricKey`
API, and also `MLDSA65`, `XWingMLKEM768X25519`, Ed25519 and the X-Wing HPKE ciphersuite,
so everything builds and tests on Linux as well. They are declared inside `#if os(Linux)`, so a macOS build never resolves them.
libsodium comes from the system: `apt install libsodium-dev`.

```sh
cd chotam/EncryptionCore
swift build && swift test
```

## The app (Phase 6a)

What this build does: create your identity (the passphrase is shown once, as numbered
words, with no copy button and hidden from screen capture), unlock it (optionally with a
key file), restore it on another Mac, lock it, forget it on this Mac; export your public
identity as a `.pqid` file or copyable text; import contacts from a file or pasted text,
see their fingerprints as 8 numbered groups, compare them, mark them verified, rename,
remove. Encrypting and decrypting arrive in Phase 6b.

It locks on quit, closing the window, screen lock, screen saver, sleep, fast user
switching, and after 1, 5, 10 (default) or 30 minutes without input in Chotam (Settings,
⌘,). All of that logic lives in `AppModel` and is unit-tested; the views only call it.
See SECURITY.md D27–D35 for every Phase 6 decision.

### Testing the app

Switch to the branch first:

```sh
cd ~/Developer/General-Projects
git fetch origin
git switch claude/charming-carson-au9fqy     # first time: git switch -c claude/charming-carson-au9fqy --track origin/claude/charming-carson-au9fqy
git pull
```

Unit tests (no Xcode window needed):

```sh
cd ~/Developer/General-Projects/chotam/EncryptionCore && swift test   # the core, plus the app's Keychain scan
cd ../AppModel && swift test                                          # view models and app rules
```

Run it from Xcode (Debug build): `open ~/Developer/General-Projects/chotam/App/Chotam.xcodeproj`,
then Product ▸ Run (⌘R). The project signs to run locally ("-"); if macOS asks whether
Chotam may access its own data after a rebuild, that's because each ad-hoc build has a
new signature (setting your own Team in Signing & Capabilities avoids it).

A Release build for the checks in SECURITY.md §8.1 (Debug builds carry `get-task-allow`
for Xcode's debugger; Release builds don't, D35):

```sh
cd ~/Developer/General-Projects/chotam/App
xcodebuild -project Chotam.xcodeproj -scheme Chotam -configuration Release \
  -derivedDataPath /tmp/chotam-build build
APP=/tmp/chotam-build/Build/Products/Release/Chotam.app
codesign -d --entitlements - "$APP"        # exactly app-sandbox + files.user-selected.read-write
codesign -dv "$APP" 2>&1 | grep flags      # flags=0x10000(runtime)
open "$APP"
```

Manual checklist (Release build unless noted):

1. **Sandbox:** create an identity; `ls ~/Library/Containers/io.github.the-alby-hub.Chotam/Data/Library/Application\ Support/Chotam/`
   shows `identity.pqid` (and `contacts.chotam` after adding a contact); nothing appears in
   `~/Library/Application Support/Chotam`.
2. **Passphrase sheet:** 7 numbered words; they can't be selected or copied (⌘C does
   nothing); a screenshot (⌘⇧5 or ⌘⇧3) shows the sheet blank; Continue is disabled until
   the box is ticked.
3. **Passphrase field:** unlock with the words typed in any case and spacing; macOS never
   offers to save a password, and the Passwords AutoFill key never appears; the field is
   empty after Unlock; a wrong word gives "Wrong passphrase or key file."
4. **Key file:** create a second identity with a key file (Forget This Mac first); unlock
   fails without the file and works with it; the file must be chosen again after a lock.
5. **Locking:** each of these locks it and the unlock screen says why: lock the screen
   (⌃⌘Q), start the screen saver, sleep (Apple menu ▸ Sleep), switch user (fast user
   switching), set Settings ▸ 1 minute and wait, close the window (Chotam quits). Also
   check that a lock during the few seconds of unlocking leaves it locked.
6. **Save panels:** Export .pqid File… saves where you chose, and asks before replacing;
   Import File… reads it back as a contact (from another identity) or refuses your own.
7. **No window restoration:** quit, relaunch: the window comes back empty, and
   `ls ~/Library/Containers/io.github.the-alby-hub.Chotam/Data/Library/Saved\ Application\ State`
   shows nothing for Chotam.
8. **No debugger on Release:** `lldb -n Chotam` while it runs fails to attach.
9. **One copy only:** `open -n "$APP"` doesn't start a second Chotam.
10. **Errors:** no message ever shows a path.

Quarantine and the save panels for encrypting and decrypting are Phase 6b's checklist
(SECURITY.md §8.1, checks 9 and 10).

## Credits

The passphrase generator uses the [EFF large wordlist](https://www.eff.org/dice) by the
Electronic Frontier Foundation, licensed under
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/). It is bundled unmodified.
