import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Your identity, unlocked: its private keys, rebuilt in memory from your passphrase
/// (SECURITY.md D17).
///
/// - The keys exist **only in memory**, only while this object is unlocked. Nothing
///   secret is ever stored: not in the Keychain, not on disk (SECURITY.md D18).
/// - `lock()` drops them. CryptoKit zeroes key storage when it's released. Call it on
///   quit, when the screen locks, on sleep and after an idle timeout (the app does,
///   Phase 6). It is also called when this object is released.
/// - After `lock()`, everything that needs a key throws `IdentityError.locked`. Unlock
///   again with `IdentityVault.unlock(passphrase:keyFile:)`.
/// - Contacts belong to the identity: their file is encrypted with a key derived from
///   your passphrase, so they're managed here, while unlocked.
///
/// Thread-safe. Contact changes and file operations are synchronous: call them off
/// the main thread.
public final class Identity: @unchecked Sendable {
    /// Your public identity: share `exportedData` or `exportedString` with contacts.
    public let publicIdentity: PublicIdentity
    let vault: IdentityVault

    private let mutex = NSLock()
    private var keys: DerivedKeys?

    init(publicIdentity: PublicIdentity, keys: DerivedKeys, vault: IdentityVault) {
        self.publicIdentity = publicIdentity
        self.keys = keys
        self.vault = vault
    }

    deinit {
        lock()
    }

    /// The name you gave it (it is in your `.pqid`, so contacts see it as a suggestion).
    public var name: String { publicIdentity.suggestedName ?? "" }

    /// Read your fingerprint to a contact so they can mark you as verified.
    public var fingerprint: Fingerprint { publicIdentity.fingerprint }

    /// Whether unlocking needs a key file as well as the passphrase.
    public var requiresKeyFile: Bool { publicIdentity.kdf.requiresKeyFile }

    // MARK: Locking

    public var isLocked: Bool {
        mutex.withLock { keys == nil }
    }

    /// Drops every private key and the contacts key from memory. Idempotent.
    ///
    /// Best effort (SECURITY.md §7.3): CryptoKit zeroes each key's storage once the last
    /// reference to it is gone. An operation already running keeps its own reference
    /// until it finishes.
    public func lock() {
        let dropped: DerivedKeys? = mutex.withLock {
            let current = keys
            keys = nil
            return current
        }
        _ = dropped  // released here, outside the lock
    }

    /// Runs `body` with the keys, or throws `.locked`.
    func withKeys<R>(_ body: (DerivedKeys) throws -> R) throws -> R {
        guard let current = mutex.withLock({ keys }) else { throw IdentityError.locked }
        return try body(current)
    }

    // MARK: Contacts

    /// All contacts, by name (ignoring case).
    public func contacts() throws(IdentityError) -> [Contact] {
        do {
            return Self.sorted(try loadContacts())
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    /// Adds a contact, always **unverified**.
    ///
    /// Refused if it's your own identity, or if a contact already has any of its
    /// keys: two contacts must never share a key (SECURITY.md D14).
    public func importContact(_ identity: PublicIdentity, name: String) throws(IdentityError) -> Contact {
        guard DisplayName.isAcceptable(name) else { throw .invalidName }
        guard !publicIdentity.sharesKey(with: identity) else { throw .isYourOwnIdentity }
        do {
            var all = try loadContacts()
            guard !all.contains(where: { $0.publicIdentity.sharesKey(with: identity) }) else {
                throw IdentityError.alreadyAContact
            }
            guard all.count < IdentityFormat.maxContacts else { throw IdentityError.tooManyContacts }
            let contact = Contact(name: name, isVerified: false, publicIdentity: identity)
            all.append(contact)
            try saveContacts(all)
            return contact
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    /// Marks a contact verified, after you compared the full fingerprint with them.
    public func markVerified(_ contact: Contact) throws(IdentityError) -> Contact {
        try update(contact) { Contact(name: $0.name, isVerified: true, publicIdentity: $0.publicIdentity) }
    }

    /// Renames a contact. Their keys and verified status don't change.
    public func rename(_ contact: Contact, to name: String) throws(IdentityError) -> Contact {
        guard DisplayName.isAcceptable(name) else { throw .invalidName }
        return try update(contact) { Contact(name: name, isVerified: $0.isVerified, publicIdentity: $0.publicIdentity) }
    }

    /// Removes a contact. Removing one that's already gone is not an error.
    public func remove(_ contact: Contact) throws(IdentityError) {
        do {
            var all = try loadContacts()
            let before = all.count
            all.removeAll { $0.publicIdentity == contact.publicIdentity }
            if all.count != before {
                try saveContacts(all)
            }
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    /// The contact whose signing key has this ID: who signed a recipient-mode file.
    func contact(signingKeyID: KeyID) throws(IdentityError) -> Contact? {
        try contacts().first { $0.publicIdentity.signingKeyID == signingKeyID }
    }

    // MARK: Implementation

    private static func sorted(_ contacts: [Contact]) -> [Contact] {
        contacts.sorted { ($0.name.lowercased(), $0.name, $0.id) < ($1.name.lowercased(), $1.name, $1.id) }
    }

    /// Reads the contacts as stored now, applies `change` to the one with the same keys,
    /// and writes the file back atomically.
    private func update(_ contact: Contact, _ change: (Contact) -> Contact) throws(IdentityError) -> Contact {
        do {
            var all = try loadContacts()
            guard let index = all.firstIndex(where: { $0.publicIdentity == contact.publicIdentity }) else {
                throw IdentityError.contactNotFound
            }
            let updated = change(all[index])
            all[index] = updated
            try saveContacts(all)
            return updated
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    private func loadContacts() throws -> [Contact] {
        let key = try withKeys { $0.contactsKey }
        guard let bytes = try vault.readFile(
            IdentityFormat.contactsFileName, limit: IdentityFormat.contactsMaxFileSize, tooLarge: .contactsDamaged)
        else { return [] }
        let loaded = try ContactsFile.decode(bytes, owner: publicIdentity.encryptionKeyID, key: key)
        // Defensive: the file is authenticated, but never trust it to keep the rules.
        var accepted: [Contact] = []
        for contact in loaded {
            guard !publicIdentity.sharesKey(with: contact.publicIdentity),
                  !accepted.contains(where: { $0.publicIdentity.sharesKey(with: contact.publicIdentity) })
            else {
                DebugLog.record(.storedRecordDamaged)
                continue
            }
            accepted.append(contact)
        }
        return accepted
    }

    private func saveContacts(_ contacts: [Contact]) throws {
        let key = try withKeys { $0.contactsKey }
        let bytes = try ContactsFile.encode(contacts, owner: publicIdentity.encryptionKeyID, key: key)
        try vault.writeFile(IdentityFormat.contactsFileName, bytes, replacing: true)
    }
}

/// Someone you exchange files with.
///
/// A contact starts **unverified**. Mark it verified only after you and they have
/// compared the whole fingerprint over a channel you trust (in person, a call where
/// you recognise their voice). Encrypting to an unverified contact needs an explicit
/// confirmation (`RecipientList`).
public struct Contact: Hashable, Sendable, Identifiable {
    /// The name you gave this contact. Only you see it.
    public let name: String
    public let isVerified: Bool
    public let publicIdentity: PublicIdentity

    public var fingerprint: Fingerprint { publicIdentity.fingerprint }

    /// Stable while the contact exists (derived from its encryption key ID).
    public var id: String { publicIdentity.encryptionKeyID.hex }
}
