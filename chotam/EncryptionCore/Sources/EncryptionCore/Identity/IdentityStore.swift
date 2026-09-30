import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Your identity and your contacts, kept in the Keychain and the Secure Enclave
/// (SECURITY.md D7, D8, D15).
///
/// The calls are synchronous. Those that touch private keys can show Touch ID or the
/// password prompt, so call them off the main thread.
public struct IdentityStore: Sendable {
    let items: any SecureItemStore
    let secureEnclave: any SecureEnclaveSigning

    /// Tests pass an in-memory store and a fake Secure Enclave (SECURITY.md D8).
    init(items: any SecureItemStore, secureEnclave: any SecureEnclaveSigning) {
        self.items = items
        self.secureEnclave = secureEnclave
    }

    #if canImport(CryptoKit) && canImport(Security)
    /// The Keychain and Secure Enclave of this Mac. Needs a signed app with Chotam's
    /// `keychain-access-groups` entitlement.
    public static let system = IdentityStore(items: KeychainItemStore(), secureEnclave: SystemSecureEnclave())
    #endif

    // MARK: Your identity

    /// Your identity, or nil if you haven't created one. Never prompts: only the
    /// public record is read.
    public func myIdentity() throws(IdentityError) -> Identity? {
        do {
            guard let data = try items.copy(.ownIdentity) else { return nil }
            let record = try OwnIdentityRecord.decode([UInt8](data))
            return Identity(
                publicIdentity: record.publicIdentity, signingKeyStorage: record.signingKeyStorage, store: self)
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    /// Creates your identity.
    ///
    /// - The ML-DSA-65 signing key is made in the Secure Enclave. Only if this Mac's
    ///   Secure Enclave can't make it does it go in the Keychain instead; that is
    ///   decided here, once, and reported in `signingKeyStorage`.
    /// - The X-Wing key is made in memory and stored in the Keychain, readable only
    ///   after user presence.
    /// - Your `.pqid` is signed once, now (one Touch ID or password prompt), so
    ///   exporting it later needs no prompt.
    ///
    /// If anything fails, nothing is left behind.
    public func createIdentity(name: String) throws(IdentityError) -> Identity {
        guard DisplayName.isAcceptable(name) else { throw .invalidName }
        // Checked on its own, outside the cleanup below: if this read fails, nothing
        // may be deleted, because an identity might exist.
        let exists: Bool
        do {
            exists = try items.copy(.ownIdentity) != nil
        } catch {
            throw identityError(for: error, parsing: false)
        }
        guard !exists else { throw .identityExists }

        do {
            // Private items without a public record are left over from a creation
            // that was interrupted (e.g. the app was killed). They belong to no identity.
            try deletePrivateItems()
            return try makeIdentity(name: name)
        } catch {
            // The public record is written last, so on failure it was never written:
            // only the private items need removing.
            try? deletePrivateItems()
            throw identityError(for: error, parsing: false)
        }
    }

    /// Permanently deletes your identity, private keys included. Files encrypted to
    /// it can never be opened again, and contacts must be sent a new identity.
    public func deleteMyIdentity() throws(IdentityError) {
        do {
            // The public record first: once it's gone the identity no longer exists,
            // even if deleting the private items below is interrupted.
            try items.delete(.ownIdentity)
            try deletePrivateItems()
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    // MARK: Contacts

    /// All contacts, by name (ignoring case). A damaged record is skipped (and logged), so one bad
    /// item can't hide the others. Never prompts.
    public func contacts() throws(IdentityError) -> [Contact] {
        do {
            var result: [Contact] = []
            for account in try items.accounts(in: .contacts) {
                let item = StoredItem(collection: .contacts, account: account)
                guard let data = try items.copy(item) else { continue }
                do {
                    let contact = try Self.contact(from: data)
                    // The record must sit under its own key ID, or it was moved.
                    guard StoredItem.contact(contact.publicIdentity.encryptionKeyID) == item else {
                        throw CoreFailure(.storedRecordDamaged)
                    }
                    result.append(contact)
                } catch {
                    DebugLog.record((error as? CoreFailure)?.reason ?? .storedRecordDamaged)
                }
            }
            return result.sorted { ($0.name.lowercased(), $0.name, $0.id) < ($1.name.lowercased(), $1.name, $1.id) }
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    /// Adds a contact, always **unverified**.
    ///
    /// Refused if it's your own identity, or if a contact already has either of its
    /// keys: two contacts must never share a key (SECURITY.md D14).
    public func importContact(_ identity: PublicIdentity, name: String) throws(IdentityError) -> Contact {
        guard DisplayName.isAcceptable(name) else { throw .invalidName }
        do {
            if let me = try myIdentity(), me.publicIdentity.sharesKey(with: identity) {
                throw IdentityError.isYourOwnIdentity
            }
            if try contacts().contains(where: { $0.publicIdentity.sharesKey(with: identity) }) {
                throw IdentityError.alreadyAContact
            }
            let contact = Contact(name: name, isVerified: false, publicIdentity: identity)
            try save(contact, replacing: false)
            return contact
        } catch let failure as SecureStoreError where failure == .duplicateItem {
            throw .alreadyAContact
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
            try items.delete(.contact(contact.publicIdentity.encryptionKeyID))
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    // MARK: Phase 5 lookups

    /// The contact whose signing key has this ID, to name the sender of a file.
    func contact(signingKeyID: KeyID) throws(IdentityError) -> Contact? {
        try contacts().first { $0.publicIdentity.signingKeyID == signingKeyID }
    }

    func signer(for identity: Identity) throws(IdentityError) -> any MessageSigner {
        do {
            guard var blob = try items.copy(.signingKey) else { throw IdentityError.noIdentity }
            defer { Wipe.data(&blob) }
            let signer: any MessageSigner
            switch identity.signingKeyStorage {
            case .secureEnclave:
                signer = try secureEnclave.loadKey(handle: blob)
            case .keychain:
                signer = SoftwareSigner(key: try MLDSA65.PrivateKey(integrityCheckedRepresentation: blob))
            }
            // Never sign with a key that isn't the one the identity advertises.
            guard KeyID.signing(signer.publicKey) == identity.publicIdentity.signingKeyID else {
                throw CoreFailure(.storedKeyMismatch)
            }
            return signer
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    func decryptionKey(for identity: Identity) throws(IdentityError) -> XWingMLKEM768X25519.PrivateKey {
        do {
            guard var blob = try items.copy(.encryptionKey) else { throw IdentityError.noIdentity }
            defer { Wipe.data(&blob) }
            // The integrity-checked form holds the seed and a hash of the public key,
            // so a damaged item fails here instead of yielding a different key.
            let key = try XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: blob)
            guard KeyID.encryption(key.publicKey) == identity.publicIdentity.encryptionKeyID else {
                throw CoreFailure(.storedKeyMismatch)
            }
            return key
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    // MARK: Implementation

    private func makeIdentity(name: String) throws -> Identity {
        // 1. The signing key: the Secure Enclave if it can, otherwise the Keychain.
        //    Only `SecureEnclaveUnavailable` falls back; every other error stops here.
        let storage: KeyStorage
        var signingItem: Data
        let signingProtection: ItemProtection
        let signer: any MessageSigner
        do {
            let created = try secureEnclave.createKey()
            storage = .secureEnclave
            signingItem = created.handle  // an SE-encrypted handle, useless off this Mac
            signingProtection = .whenUnlocked  // the Secure Enclave enforces user presence itself
            signer = created.signer
        } catch is SecureEnclaveUnavailable {
            let key = try MLDSA65.PrivateKey()
            storage = .keychain
            signingItem = key.integrityCheckedRepresentation  // seed ‖ SHA3-256(public key)
            signingProtection = .userPresence
            signer = SoftwareSigner(key: key)
        }
        defer { Wipe.data(&signingItem) }

        // 2. The encryption key. Always the Keychain: the Secure Enclave has no X-Wing.
        let xwing = try XWingMLKEM768X25519.PrivateKey.generate()
        var encryptionItem = xwing.integrityCheckedRepresentation
        defer { Wipe.data(&encryptionItem) }

        // 3. The self-signed .pqid. Signing with a Secure Enclave key prompts once here.
        let body = try PQIDCodec.body(
            encryptionKey: [UInt8](xwing.publicKey.rawRepresentation),
            signingKey: [UInt8](signer.publicKey.rawRepresentation),
            name: name)
        let signature = try signer.signature(for: PQIDCodec.signedMessage(body: body))
        // Parse our own output with the import parser: we never store an identity
        // that a contact couldn't import.
        let publicIdentity = try PQIDCodec.decode(PQIDCodec.assemble(body: body, signature: signature))

        // 4. Private items first, the public record last: until it exists, there is
        //    no identity, so an interruption can't leave a half-made one in use.
        try items.add(encryptionItem, as: .encryptionKey, protection: .userPresence)
        try items.add(signingItem, as: .signingKey, protection: signingProtection)
        let record = OwnIdentityRecord(signingKeyStorage: storage, publicIdentity: publicIdentity)
        try items.add(Data(record.encode()), as: .ownIdentity, protection: .whenUnlocked)

        return Identity(publicIdentity: publicIdentity, signingKeyStorage: storage, store: self)
    }

    private func deletePrivateItems() throws {
        try items.delete(.encryptionKey)
        try items.delete(.signingKey)
    }

    private static func contact(from data: Data) throws -> Contact {
        let record = try ContactRecord.decode([UInt8](data))
        return Contact(name: record.name, isVerified: record.isVerified, publicIdentity: record.publicIdentity)
    }

    private func save(_ contact: Contact, replacing: Bool) throws {
        let record = ContactRecord(
            name: contact.name, isVerified: contact.isVerified, publicIdentity: contact.publicIdentity)
        let data = Data(try record.encode())
        let item = StoredItem.contact(contact.publicIdentity.encryptionKeyID)
        if replacing {
            guard try items.replace(data, for: item) else { throw IdentityError.contactNotFound }
        } else {
            try items.add(data, as: item, protection: .whenUnlocked)
        }
    }

    /// Reads the contact as stored now (not the caller's possibly stale copy), applies
    /// `change`, and writes it back in one atomic replace.
    private func update(_ contact: Contact, _ change: (Contact) -> Contact) throws(IdentityError) -> Contact {
        do {
            let item = StoredItem.contact(contact.publicIdentity.encryptionKeyID)
            guard let data = try items.copy(item) else { throw IdentityError.contactNotFound }
            let current = try Self.contact(from: data)
            // Same keys, or it isn't the contact the caller meant.
            guard current.publicIdentity == contact.publicIdentity else { throw IdentityError.contactNotFound }
            let updated = change(current)
            try save(updated, replacing: true)
            return updated
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }
}
