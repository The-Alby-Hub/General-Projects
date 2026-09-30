import Foundation
#if canImport(os)
import os
#endif

/// The only error a caller ever sees when opening a file fails.
///
/// Wrong password, wrong key, bad signature, tampering and malformed input are
/// deliberately indistinguishable, so the UI can never become an oracle that
/// tells an attacker which check their modified file got past.
public struct DecryptionFailed: Error, LocalizedError, Equatable, Sendable {
    public static let message = "Decryption failed: file is damaged or not for you."

    public init() {}

    public var errorDescription: String? { Self.message }
}

/// Internal failure carrying a precise reason for tests and debug logs.
///
/// It never crosses the public API: mode-level entry points convert it with
/// `publicDecryptionError(_:)`. Reasons are fixed strings and never carry
/// key material, passwords, plaintext or filenames.
struct CoreFailure: Error, Equatable {
    enum Reason: String, Sendable {
        // Header parsing (FORMAT.md §7)
        case truncatedHeader
        case badMagic
        case unsupportedVersion
        case unknownMode
        case headerLengthOutOfRange
        case headerLengthMismatch
        case trailingHeaderBytes
        case unsupportedChunkSize
        case fieldSizeMismatch
        case argon2ParametersOutOfRange
        case recipientCountOutOfRange
        case duplicateRecipient
        // Keys
        case invalidKeyLength
        case commitmentMismatch
        // Body
        case chunkAuthenticationFailed
        case truncatedBody
        case tooManyChunks
        case nonCanonicalFinalChunk
        case malformedMetadata
        // Encrypt-side input validation
        case invalidFilename
        case invalidHeaderFields
        // I/O and anything unexpected
        case readFailed
        case writeFailed
        case unexpected
    }

    let reason: Reason

    init(_ reason: Reason) {
        self.reason = reason
    }
}

enum DebugLog {
    #if canImport(os)
    private static let logger = Logger(subsystem: "app.chotam.EncryptionCore", category: "crypto")
    #endif

    /// Logs a failure reason at debug level. Only the fixed enum string is logged.
    static func record(_ reason: CoreFailure.Reason) {
        #if canImport(os)
        logger.debug("operation failed: \(reason.rawValue, privacy: .public)")
        #endif
    }
}

/// Maps any internal error to the single public error, logging only the reason.
func publicDecryptionError(_ error: any Error) -> DecryptionFailed {
    // Foundation or CryptoKit errors are logged as "unexpected" rather than by
    // description, so no path, filename or library message ever reaches the log.
    DebugLog.record((error as? CoreFailure)?.reason ?? .unexpected)
    return DecryptionFailed()
}
