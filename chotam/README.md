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
| 3 | Atomic file processor | — |
| 4 | Identities, Keychain / Secure Enclave, fingerprints | — |
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
      Resources/                 EFF large wordlist (CC-BY 3.0 US)
    Tests/EncryptionCoreTests/   XCTest
      Vectors/                   golden .enc files from an independent implementation (FORMAT.md §8)
```

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

Password-mode tests run Argon2id for real. Most use the cheapest cost a file may declare
(ops 3, 256 MiB). A few use the production preset (ops 4, 1 GiB) and take several
seconds each.

**Linux** (development convenience only). Needs a Swift 6.2 toolchain. The manifest then adds
[apple/swift-crypto](https://github.com/apple/swift-crypto) 5.0.0 and swift-asn1 1.7.3,
both pinned exactly. They provide the same `AES.GCM` / `HKDF` / `SHA256` / `SymmetricKey`
API. They are declared inside `#if os(Linux)`, so a macOS build never resolves them.
libsodium comes from the system: `apt install libsodium-dev`.

```sh
cd chotam/EncryptionCore
swift build && swift test
```

## Credits

The passphrase generator uses the [EFF large wordlist](https://www.eff.org/dice) by the
Electronic Frontier Foundation, licensed under
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/). It is bundled unmodified.
