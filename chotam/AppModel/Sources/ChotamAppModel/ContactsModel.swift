import EncryptionCore
import Foundation
import Observation

/// An identity read from a `.pqid` file or a pasted string, not yet a contact: the
/// import sheet shows its fingerprint and asks for a name first.
public struct PendingContact: Sendable, Equatable {
    public let publicIdentity: PublicIdentity
    /// The name its owner chose: untrusted, only a suggestion to prefill (§5.19).
    public let suggestedName: String
    public let fingerprint: FingerprintDisplay

    public init(_ publicIdentity: PublicIdentity) {
        self.publicIdentity = publicIdentity
        suggestedName = publicIdentity.suggestedName ?? ""
        fingerprint = FingerprintDisplay(groups: publicIdentity.fingerprint.groups)
    }
}

/// Your contacts, while your identity is unlocked (SECURITY.md D15, D16).
///
/// Every change goes straight to the encrypted contacts file through the identity;
/// `contacts` is re-read after each one. Imports always start unverified.
@MainActor
@Observable
public final class ContactsModel {
    /// Sorted by name.
    public private(set) var contacts: [Contact] = []
    /// The last error, as public text.
    public var message: String?

    private let identity: Identity

    init(identity: Identity) {
        self.identity = identity
        reload()
    }

    public func reload() {
        do {
            contacts = try identity.contacts().sorted {
                $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
        } catch {
            contacts = []
            message = UserMessage.text(for: error)
        }
    }

    public func contact(id: Contact.ID) -> Contact? {
        contacts.first { $0.id == id }
    }

    // MARK: Importing

    /// Reads a `.pqid` file's bytes. Nil (and `message` set) if it isn't one.
    public func prepareImport(data: Data) -> PendingContact? {
        prepare { () throws -> PublicIdentity in try IdentityImport.parse(data: data) }
    }

    /// Reads a pasted Base64 identity. Nil (and `message` set) if it isn't one.
    public func prepareImport(string: String) -> PendingContact? {
        prepare { () throws -> PublicIdentity in try IdentityImport.parse(string: string) }
    }

    /// Adds the contact, unverified, under `name`.
    @discardableResult
    public func add(_ pending: PendingContact, name: String) -> Contact? {
        change { () throws -> Contact in
            try identity.importContact(pending.publicIdentity, name: Self.clean(name))
        }
    }

    // MARK: Changing

    /// After the user compared all 8 fingerprint groups with the contact.
    @discardableResult
    public func markVerified(_ contact: Contact) -> Contact? {
        change { () throws -> Contact in try identity.markVerified(contact) }
    }

    @discardableResult
    public func rename(_ contact: Contact, to name: String) -> Contact? {
        change { () throws -> Contact in try identity.rename(contact, to: Self.clean(name)) }
    }

    /// Their files will no longer open (unknown sender, D20); files to them can't be made.
    @discardableResult
    public func remove(_ contact: Contact) -> Bool {
        change { () throws -> Bool in
            try identity.remove(contact)
            return true
        } ?? false
    }

    // MARK: Private

    private func prepare(_ parse: () throws -> PublicIdentity) -> PendingContact? {
        do {
            message = nil
            return PendingContact(try parse())
        } catch {
            message = UserMessage.text(for: error)
            return nil
        }
    }

    private func change<T>(_ body: () throws -> T) -> T? {
        defer { reload() }
        do {
            message = nil
            return try body()
        } catch {
            message = UserMessage.text(for: error)
            return nil
        }
    }

    private static func clean(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
