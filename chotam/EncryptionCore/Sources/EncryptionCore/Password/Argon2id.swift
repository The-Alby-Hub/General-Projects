import Clibsodium
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Password → 256-bit input keying material with Argon2id (FORMAT.md §4.1).
///
/// This calls libsodium's C `crypto_pwhash` directly. swift-sodium's Swift wrapper
/// (`PWHash.hash`) converts each password byte with `Int8.init`, which traps on
/// any byte ≥ 0x80 (every non-ASCII password), and copies the password into an
/// array we can't wipe. See SECURITY.md D11.
enum Argon2id {
    struct Cost: Equatable, Sendable {
        let opsLimit: UInt64
        /// Bytes.
        let memLimit: UInt64

        /// libsodium's SENSITIVE preset (ops 4, 1 GiB): what encryption always writes.
        /// Written out rather than read from libsodium at run time, so a future
        /// library release can't silently change what files contain; a test checks
        /// the two still agree.
        static let sensitive = Cost(opsLimit: 4, memLimit: 1 << 30)

        /// The cheapest cost a v1 file may declare (ops 3, 256 MiB). Tests use it to stay fast.
        static let minimumAccepted = Cost(
            opsLimit: FormatV1.argon2OpsLimitRange.lowerBound,
            memLimit: FormatV1.argon2MemLimitRange.lowerBound)

        /// Within the v1 window (FORMAT.md §2.3). Checked again here, not just by
        /// the parser, so no caller can ask for a huge or trivial cost.
        var isAccepted: Bool {
            FormatV1.argon2OpsLimitRange.contains(opsLimit)
                && FormatV1.argon2MemLimitRange.contains(memLimit)
        }
    }

    /// libsodium's own SENSITIVE values, for the test that pins `Cost.sensitive`.
    static var librarySensitiveCost: Cost {
        Cost(
            opsLimit: UInt64(crypto_pwhash_opslimit_sensitive()),
            memLimit: UInt64(crypto_pwhash_memlimit_sensitive()))
    }

    /// libsodium's salt size, for the test that pins `FormatV1.argon2SaltSize`.
    static var librarySaltSize: Int { Int(crypto_pwhash_saltbytes()) }

    /// Derives the 32-byte IKM. Takes about a second and `cost.memLimit` bytes of RAM
    /// at the SENSITIVE preset, so callers run it off the main thread.
    ///
    /// - Parameters:
    ///   - password: Normalised to Unicode NFC, then encoded as UTF-8. The same
    ///     password typed as precomposed "é" or as "e" + combining accent gives the
    ///     same key. Nothing is trimmed: spaces are part of the password.
    ///   - salt: The file's random 16-byte Argon2id salt.
    static func deriveIKM(password: String, salt: [UInt8], cost: Cost) throws -> SymmetricKey {
        guard salt.count == FormatV1.argon2SaltSize else {
            throw CoreFailure(.fieldSizeMismatch)
        }
        guard cost.isAccepted else {
            throw CoreFailure(.argon2ParametersOutOfRange)
        }
        // sodium_init is idempotent and thread-safe; 0 or 1 means ready.
        guard sodium_init() >= 0 else {
            throw CoreFailure(.keyDerivationFailed)
        }

        // The password bytes go straight into a buffer we own and wipe, never into
        // a Swift array. The normalised String itself can't be wiped (SECURITY.md §7.3).
        let normalized = password.precomposedStringWithCanonicalMapping
        let passwordLength = normalized.utf8.count
        // At least 1 byte so the pointer is never nil; libsodium reads `passwordLength` bytes.
        let secret = UnsafeMutableRawBufferPointer.allocate(byteCount: max(passwordLength, 1), alignment: 1)
        defer {
            Wipe.raw(secret)
            secret.deallocate()
        }
        _ = secret.initializeMemory(as: UInt8.self, repeating: 0)
        for (offset, byte) in normalized.utf8.enumerated() {
            secret[offset] = byte
        }

        let output = UnsafeMutableRawBufferPointer.allocate(byteCount: FormatV1.ikmSize, alignment: 1)
        defer {
            Wipe.raw(output)
            output.deallocate()
        }
        _ = output.initializeMemory(as: UInt8.self, repeating: 0)

        let status = salt.withUnsafeBufferPointer { saltBuffer in
            // Argon2id v1.3 (argon2id13), explicitly rather than libsodium's
            // "default" alias. libsodium fixes parallelism at 1 lane.
            crypto_pwhash(
                output.baseAddress!.assumingMemoryBound(to: UInt8.self),
                UInt64(FormatV1.ikmSize),
                secret.baseAddress!.bindMemory(to: CChar.self, capacity: secret.count),
                UInt64(passwordLength),
                saltBuffer.baseAddress!,
                cost.opsLimit,
                Int(cost.memLimit),
                crypto_pwhash_alg_argon2id13())
        }
        // Non-zero means libsodium couldn't allocate the memory (or rejected a parameter).
        guard status == 0 else {
            throw CoreFailure(.keyDerivationFailed)
        }
        // SymmetricKey copies the bytes into its own storage, which CryptoKit zeroes
        // on release. Our buffer is wiped by the defer above.
        return SymmetricKey(data: UnsafeRawBufferPointer(output))
    }
}
