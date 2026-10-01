import Foundation

/// Everything that can go wrong with identities and contacts.
///
/// These concern your own identity, your own files and public identities, so they can
/// be precise without helping an attacker: an unlock attempt checks your passphrase
/// against your own public `.pqid`, which anyone holding it can do offline anyway.
/// Messages are fixed strings and never include keys, names, passphrases or paths.
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
    /// Chotam keeps at most 500 contacts.
    case tooManyContacts
    /// This Mac already has an identity. Forget it first to create or restore another.
    case identityExists
    /// This Mac has no identity yet: create one, or restore yours.
    case noIdentity
    /// Not 7 to 10 different words from Chotam's word list.
    case invalidPassphrase
    /// The passphrase (or the key file) doesn't produce this identity.
    case wrongPassphrase
    /// This identity was created with a key file; choose it to unlock.
    case keyFileRequired
    /// This identity doesn't use a key file; unlock with the passphrase alone.
    case keyFileNotUsed
    /// The key file couldn't be read, or is empty.
    case keyFileUnusable
    /// The identity was locked: its keys have been wiped from memory. Unlock it again.
    case locked
    /// Not enough free memory to derive the keys (about 1 GiB is needed).
    case notEnoughMemory
    /// The contacts file is damaged or belongs to another identity.
    case contactsDamaged
    /// Chotam couldn't read or write its files.
    case storageFailed
    case unexpected

    public var errorDescription: String? {
        switch self {
        case .invalidIdentity: "This isn't a valid Chotam identity, or it was damaged."
        case .unsupportedVersion: "This identity was made by a newer version of Chotam."
        case .invalidName: "Names must be 1 to 64 bytes long and can't contain control characters."
        case .isYourOwnIdentity: "This is your own identity."
        case .alreadyAContact: "One of this identity's keys already belongs to a contact."
        case .contactNotFound: "This contact no longer exists."
        case .tooManyContacts: "Chotam can keep at most 500 contacts."
        case .identityExists: "This Mac already has an identity."
        case .noIdentity: "There's no identity on this Mac yet."
        case .invalidPassphrase: "A passphrase is 7 to 10 different words from Chotam's word list."
        case .wrongPassphrase: "Wrong passphrase or key file."
        case .keyFileRequired: "This identity needs its key file."
        case .keyFileNotUsed: "This identity doesn't use a key file."
        case .keyFileUnusable: "The key file can't be read, or is empty."
        case .locked: "Your identity is locked. Unlock it with your passphrase."
        case .notEnoughMemory: "There isn't enough free memory to unlock the identity."
        case .contactsDamaged: "The contacts file is damaged."
        case .storageFailed: "Chotam couldn't read or write its files."
        case .unexpected: "Something unexpected went wrong."
        }
    }
}

/// Maps any internal error to `IdentityError`, logging only a fixed reason.
///
/// - Parameter parsing: true when the bytes came from a `.pqid` (an import, or the
///   identity file), so a format failure means "invalid identity". False otherwise,
///   where a format failure is unexpected.
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
        // Argon2id couldn't allocate the memory the identity's KDF asks for.
        case .keyDerivationFailed:
            return .notEnoughMemory
        case .contactsDamaged:
            return .contactsDamaged
        case .wrongPassphrase:
            return .wrongPassphrase
        case .readFailed, .writeFailed:
            return .storageFailed
        default:
            return .unexpected
        }
    case is FileProblem:
        DebugLog.record(.writeFailed)
        return .storageFailed
    default:
        DebugLog.record(.unexpected)
        return .unexpected
    }
}
