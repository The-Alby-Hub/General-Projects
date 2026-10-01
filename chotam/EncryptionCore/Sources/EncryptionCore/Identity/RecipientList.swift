/// The contacts a file will be encrypted to (`EncryptionMode.recipients`), besides you.
///
/// Encrypting to an **unverified** contact can't happen by accident. `init(_:)`
/// refuses any list that contains one, and hands back an `UnverifiedRecipientsRequest`
/// naming exactly those contacts. Its `confirm()` is the only way to get a list that
/// includes them, and the app calls it only after the user confirmed, in a dialog,
/// that they want to encrypt to these unverified contacts. There is no flag or
/// default parameter that skips this.
public struct RecipientList: Sendable, Equatable {
    public let contacts: [Contact]

    /// A list of verified contacts.
    ///
    /// - Throws: `.needsConfirmation` if any contact is unverified; `.noRecipients`,
    ///   `.tooManyRecipients` (over 63) or `.duplicateRecipient` otherwise.
    public init(_ contacts: [Contact]) throws(RecipientSelectionError) {
        try Self.validate(contacts)
        let unverified = contacts.filter { !$0.isVerified }
        guard unverified.isEmpty else {
            throw .needsConfirmation(UnverifiedRecipientsRequest(contacts: contacts, unverifiedContacts: unverified))
        }
        self.contacts = contacts
    }

    fileprivate init(confirmed contacts: [Contact]) {
        self.contacts = contacts
    }

    private static func validate(_ contacts: [Contact]) throws(RecipientSelectionError) {
        guard !contacts.isEmpty else { throw .noRecipients }
        // A v1 header holds at most 64 recipient stanzas (FORMAT.md §2.3), and your
        // own identity always takes one, so you can open what you sent.
        guard contacts.count <= FormatV1.maxContactRecipients else { throw .tooManyRecipients }
        var encryptionIDs = Set<KeyID>()
        var signingIDs = Set<KeyID>()
        for contact in contacts {
            guard encryptionIDs.insert(contact.publicIdentity.encryptionKeyID).inserted,
                  signingIDs.insert(contact.publicIdentity.signingKeyID).inserted
            else { throw .duplicateRecipient }
        }
    }
}

/// Returned when a selection includes unverified contacts. Show `unverifiedContacts`
/// to the user and call `confirm()` only if they choose to go ahead.
public struct UnverifiedRecipientsRequest: Sendable, Equatable {
    /// The whole selection, in order.
    let contacts: [Contact]
    /// The contacts whose fingerprints haven't been verified. Name them in the dialog.
    public let unverifiedContacts: [Contact]

    /// The user confirmed encrypting to `unverifiedContacts`. Returns the full list.
    public func confirm() -> RecipientList {
        RecipientList(confirmed: contacts)
    }
}

public enum RecipientSelectionError: Error, Equatable, Sendable {
    /// Some contacts are unverified: ask the user, then `request.confirm()`.
    case needsConfirmation(UnverifiedRecipientsRequest)
    case noRecipients
    /// More than 63 contacts (the 64th stanza is always yours).
    case tooManyRecipients
    /// The same contact (or a key of theirs) appears twice.
    case duplicateRecipient
}
