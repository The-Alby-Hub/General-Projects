import EncryptionCore
import Foundation

/// Problems found by the app itself, with fixed messages.
public enum AppProblem: Error, Equatable, Sendable, LocalizedError {
    /// A `.pqid` file couldn't be read, or is far larger than any identity.
    case identityFileUnreadable
    /// Pasted text is empty.
    case nothingToImport
    /// An exported identity couldn't be saved where the user chose.
    case exportFailed
    /// Something else is still running (one operation at a time, SECURITY.md D33).
    case busy

    public var errorDescription: String? {
        switch self {
        case .identityFileUnreadable: "The identity file couldn't be read."
        case .nothingToImport: "Paste an identity first."
        case .exportFailed: "Your identity couldn't be saved there. Choose another place."
        case .busy: "Chotam is still busy. Try again when it's done."
        }
    }
}

/// The text to show for an error (SECURITY.md §8): the public message of Chotam's own
/// errors, exactly as the core gives it, and a fixed text for anything else. A system
/// error's own description can contain paths, so it's never shown.
public enum UserMessage {
    public static let generic = "Something went wrong. Nothing was changed."

    public static func text(for error: any Error) -> String {
        let message: String? =
            switch error {
            case let error as IdentityError: error.errorDescription
            case let error as EncryptionError: error.errorDescription
            case let error as DecryptionError: error.errorDescription
            case let error as FileProblem: error.errorDescription
            case let error as AppProblem: error.errorDescription
            case let error as RecipientSelectionError: recipientText(error)
            default: nil
            }
        return message ?? generic
    }

    private static func recipientText(_ error: RecipientSelectionError) -> String {
        switch error {
        case .needsConfirmation: "Some recipients aren't verified yet."
        case .noRecipients: "Choose at least one recipient."
        case .tooManyRecipients: "Choose at most 63 recipients."
        case .duplicateRecipient: "A recipient was chosen twice."
        }
    }
}
