import Foundation

/// Where Chotam keeps its identity and contacts: small named blobs, each with a
/// protection level (SECURITY.md D7, D8, D15).
///
/// The real store is the data-protection Keychain (`KeychainItemStore`). It needs a
/// signed app with a `keychain-access-groups` entitlement, which `swift test` doesn't
/// have. So all identity and contact logic is written against this protocol and
/// unit-tested with an in-memory store; the Keychain itself is covered by the
/// app-hosted Xcode tests (Phase 6).
protocol SecureItemStore: Sendable {
    /// Adds a new item. Throws `SecureStoreError.duplicateItem` if it exists.
    func add(_ data: Data, as item: StoredItem, protection: ItemProtection) throws
    /// Atomically replaces an existing item's data, keeping its protection.
    /// Returns false, and changes nothing, if the item doesn't exist.
    func replace(_ data: Data, for item: StoredItem) throws -> Bool
    /// The item's data, or nil if it doesn't exist. Reading an item protected by
    /// `.userPresence` shows the Touch ID / password prompt.
    func copy(_ item: StoredItem) throws -> Data?
    /// Deletes the item. Deleting a missing item is not an error.
    func delete(_ item: StoredItem) throws
    /// The account names of every item in a collection. Never prompts.
    func accounts(in collection: StoredItem.Collection) throws -> [String]
}

/// How an item is protected, on top of `WhenUnlockedThisDeviceOnly` (which every
/// item gets: readable only while the Mac is unlocked, never synced or migrated).
enum ItemProtection: Sendable, Equatable {
    /// Private key material: each read needs Touch ID or the login password.
    case userPresence
    /// Public data and Secure Enclave key handles (the SE enforces its own access control).
    case whenUnlocked
}

/// A named item. `collection` is the Keychain service, `account` the item's name.
struct StoredItem: Hashable, Sendable {
    enum Collection: String, Sendable {
        case identity = "app.chotam.identity"
        case contacts = "app.chotam.contacts"
    }

    let collection: Collection
    let account: String

    /// The X-Wing private key, integrity-checked form (seed ‖ SHA3-256 of the public key).
    static let encryptionKey = StoredItem(collection: .identity, account: "encryption")
    /// The ML-DSA-65 key: a Secure Enclave handle, or (fallback) the integrity-checked seed.
    static let signingKey = StoredItem(collection: .identity, account: "signing")
    /// The own identity's public record (FORMAT.md §10). Written last: its presence
    /// is what makes an identity exist.
    static let ownIdentity = StoredItem(collection: .identity, account: "public")

    static func contact(_ encryptionKeyID: KeyID) -> StoredItem {
        StoredItem(collection: .contacts, account: encryptionKeyID.hex)
    }
}

enum SecureStoreError: Error, Equatable {
    case duplicateItem
    /// The user dismissed the Touch ID / password prompt.
    case cancelled
    /// Anything else (a missing entitlement, a locked Keychain, …). The status code
    /// is logged at debug level only.
    case unavailable
}
