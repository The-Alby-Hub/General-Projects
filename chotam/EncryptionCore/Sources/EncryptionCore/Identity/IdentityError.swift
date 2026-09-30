import Foundation

/// Everything that can go wrong with identities and contacts.
///
/// Public identities are public data, so these can be precise without helping an
/// attacker. Messages are fixed strings and never include keys, names or paths.
public enum IdentityError: Error, LocalizedError, Equatable, Sendable {
    /// Not a valid Chotam identity: malformed, damaged, or its self-signature doesn't verify.
    case invalidIdentity
    /// Made by a newer version of Chotam.
    case unsupportedVersion
    /// A name must be 1 to 64 bytes of text, with no control characters.
    case invalidName
    /// That's your own identity, not a contact.
    case isYourOwnIdentity
    /// A contact already has one of this identity's keys.
    case alreadyAContact
    /// The contact no longer exists (it was removed).
    case contactNotFound
    /// You already have an identity. Delete it first to make a new one.
    case identityExists
    /// You haven't created an identity yet.
    case noIdentity
    /// Touch ID or the password prompt was cancelled.
    case cancelled
    /// The Keychain or Secure Enclave couldn't be used.
    case secureStorageUnavailable
    case unexpected

    public var errorDescription: String? {
        switch self {
        case .invalidIdentity: "This isn't a valid Chotam identity, or it was damaged."
        case .unsupportedVersion: "This identity was made by a newer version of Chotam."
        case .invalidName: "Names must be 1 to 64 bytes long and can't contain control characters."
        case .isYourOwnIdentity: "This is your own identity."
        case .alreadyAContact: "One of this identity's keys already belongs to a contact."
        case .contactNotFound: "This contact no longer exists."
        case .identityExists: "You already have an identity."
        case .noIdentity: "You don't have an identity yet."
        case .cancelled: "Cancelled."
        case .secureStorageUnavailable: "The Keychain couldn't be used."
        case .unexpected: "Something unexpected went wrong."
        }
    }
}

/// Maps any internal error to `IdentityError`, logging only a fixed reason.
///
/// - Parameter parsing: true when the bytes came from outside (an import), so a
///   format failure means "invalid identity". False when they came from Chotam's
///   own Keychain items, where a format failure is unexpected damage.
func identityError(for error: any Error, parsing: Bool) -> IdentityError {
    switch error {
    case let error as IdentityError:
        return error
    case let failure as CoreFailure:
        DebugLog.record(failure.reason)
        switch failure.reason {
        case .identityUnsupportedVersion where parsing:
            return .unsupportedVersion
        case .identityTooLarge, .identityBadEncoding, .identityBadMagic, .identityUnsupportedVersion,
             .identityMalformed, .identityTrailingBytes, .identityInvalidName, .identityInvalidKey,
             .identityBadSignature:
            return parsing ? .invalidIdentity : .unexpected
        default:
            return .unexpected
        }
    case let failure as SecureStoreError:
        DebugLog.record(.unexpected)
        switch failure {
        case .cancelled: return .cancelled
        case .duplicateItem: return .unexpected
        case .unavailable: return .secureStorageUnavailable
        }
    default:
        if isUserCancellation(error) { return .cancelled }
        DebugLog.record(.unexpected)
        return .unexpected
    }
}

/// Whether an error from LocalAuthentication, the Keychain or the Secure Enclave
/// means the user dismissed the Touch ID / password prompt. Best-effort: the
/// app-hosted tests (Phase 6) confirm which errors CryptoKit actually surfaces.
func isUserCancellation(_ error: any Error, depth: Int = 0) -> Bool {
    let ns = error as NSError
    // LAError.userCancel (-2), .systemCancel (-4), .appCancel (-9)
    if ns.domain == "com.apple.LocalAuthentication", [-2, -4, -9].contains(ns.code) { return true }
    // errSecUserCanceled
    if ns.domain == "NSOSStatusErrorDomain", ns.code == -128 { return true }
    if depth < 4, let underlying = ns.userInfo[NSUnderlyingErrorKey] as? any Error {
        return isUserCancellation(underlying, depth: depth + 1)
    }
    return false
}
