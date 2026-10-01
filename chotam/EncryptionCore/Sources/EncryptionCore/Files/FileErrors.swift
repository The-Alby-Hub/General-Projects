import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A problem with the files or folders involved, rather than with the password
/// or the encrypted contents.
///
/// These say nothing about a key or a file's integrity, so they can be shown as
/// they are (SECURITY.md D13). Messages are fixed and never include a path.
public enum FileProblem: Error, LocalizedError, Equatable, Sendable {
    /// The input is a folder, a package or something else that isn't a regular file.
    case inputNotAFile
    /// Something already has the output's name, and replacing it wasn't allowed.
    case outputExists
    /// The destination is the input file itself, a folder where a file was expected,
    /// a symbolic link, or a folder that doesn't exist.
    case invalidDestination
    /// The system refused access, e.g. outside what the sandbox granted.
    case accessDenied
    /// The input couldn't be read.
    case readFailed
    /// The output couldn't be written: a full disk, a removed volume, and so on.
    case writeFailed

    public var errorDescription: String? {
        switch self {
        case .inputNotAFile:
            "Chotam works on single files, not folders or packages."
        case .outputExists:
            "A file with that name already exists. Nothing was overwritten."
        case .invalidDestination:
            "The result can't be saved there. Choose a different name or folder."
        case .accessDenied:
            "Chotam doesn't have permission to use that location."
        case .readFailed:
            "The file couldn't be read."
        case .writeFailed:
            "The result couldn't be saved. The disk may be full or disconnected. Nothing was changed."
        }
    }
}

/// Why `FileProcessor.encrypt` failed. Encryption works on the user's own file, so
/// precise reasons aren't an oracle for anyone.
public enum EncryptionError: Error, LocalizedError, Equatable, Sendable {
    /// Rejected by `PasswordPolicy` (SECURITY.md D6).
    case weakPassword
    /// The file's name can't be stored safely (control or bidirectional characters,
    /// FORMAT.md §3), or the `.enc` name would be too long for the file system.
    case invalidFilename
    /// Argon2id couldn't get its memory (about 1 GiB).
    case notEnoughMemory
    case file(FileProblem)
    /// Recipient mode: the signing identity is locked (`.locked`), or its contacts file
    /// can't be read (`.contactsDamaged`, `.storageFailed`).
    case identity(IdentityError)
    /// Recipient mode: a chosen recipient is no longer one of the signing identity's
    /// contacts (removed since the list was made, or the list came from another
    /// identity). Choose the recipients again.
    case recipientsChanged
    /// The operation was cancelled. Nothing was written; the original is untouched.
    case cancelled
    /// Anything else, e.g. a file over the format's 256 TiB limit. The original is untouched.
    case unexpected

    public var errorDescription: String? {
        switch self {
        case .weakPassword:
            "This password is too weak. Use at least 14 characters without obvious patterns, or a passphrase of 6 or more words."
        case .invalidFilename:
            "This file's name can't be stored safely. Rename the file and try again."
        case .notEnoughMemory:
            "Not enough free memory. Encrypting needs about 1 GB; quit other apps and try again."
        case .file(let problem):
            problem.errorDescription
        case .identity(let problem):
            problem.errorDescription
        case .recipientsChanged:
            "Your contacts changed since you chose the recipients. Choose them again."
        case .cancelled:
            "Encryption was cancelled. Nothing was saved, and the original file is unchanged."
        case .unexpected:
            "Encryption failed unexpectedly. The original file is unchanged."
        }
    }
}

/// Why `FileProcessor.decrypt` failed.
///
/// A wrong password or key, a file that isn't for you, a bad signature, tampering, a
/// malformed or truncated file and every other problem with the encrypted contents are
/// all `.failed`, with the one generic message. Only problems that say nothing about
/// the key or the contents get their own case (SECURITY.md D13). The one recipient-mode
/// exception is `.unknownSender` (SECURITY.md D20).
public enum DecryptionError: Error, LocalizedError, Equatable, Sendable {
    /// "Decryption failed: file is damaged or not for you."
    case failed
    /// Argon2id couldn't get the memory the file's header asks for (at most 1 GiB).
    case notEnoughMemory
    case file(FileProblem)
    /// Recipient mode: the file is for you, but it's signed by someone who is neither
    /// you nor one of your contacts, so its signature can't be checked and it isn't
    /// opened (SECURITY.md D20). It reveals only public header data and whether that
    /// signer is in your contacts.
    case unknownSender
    /// Recipient mode: your identity is locked (`.locked`), or its contacts file can't
    /// be read (`.contactsDamaged`, `.storageFailed`). Nothing about the file.
    case identity(IdentityError)
    /// The operation was cancelled. Nothing was written.
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .failed:
            DecryptionFailed.message
        case .notEnoughMemory:
            "Not enough free memory. Opening this file needs up to 1 GB; quit other apps and try again."
        case .file(let problem):
            problem.errorDescription
        case .unknownSender:
            "This file is signed by someone who isn't in your contacts, so Chotam won't open it."
        case .identity(let problem):
            problem.errorDescription
        case .cancelled:
            "Decryption was cancelled. Nothing was saved."
        }
    }
}

extension FileProblem {
    /// Maps a POSIX error number, keeping only the distinctions the UI needs.
    static func posix(_ code: Int32, otherwise fallback: FileProblem) -> FileProblem {
        switch code {
        case EACCES, EPERM, EROFS: .accessDenied
        case EEXIST: .outputExists
        default: fallback
        }
    }

    /// Maps a Foundation error without keeping its description, which can contain paths.
    static func classify(_ error: any Error, otherwise fallback: FileProblem) -> FileProblem {
        if let problem = error as? FileProblem { return problem }
        let ns = error as NSError
        if ns.domain == NSPOSIXErrorDomain {
            return posix(Int32(truncatingIfNeeded: ns.code), otherwise: fallback)
        }
        if ns.domain == NSCocoaErrorDomain {
            switch ns.code {
            case CocoaError.Code.fileReadNoPermission.rawValue,
                 CocoaError.Code.fileWriteNoPermission.rawValue,
                 CocoaError.Code.fileWriteVolumeReadOnly.rawValue:
                return .accessDenied
            default:
                break
            }
        }
        return fallback
    }
}
