#if canImport(Security)
import Foundation
import Security

/// The real `SecureItemStore`: generic-password items in the data-protection Keychain
/// (SECURITY.md D7, D15).
///
/// Every item is `WhenUnlockedThisDeviceOnly` (readable only while the Mac is unlocked,
/// never synced to iCloud, never restored to another Mac) and not synchronizable.
/// Items holding private key material also need user presence (Touch ID or the login
/// password) for every read. Only apps signed into Chotam's keychain access group
/// can read or change any of them, which is why the app needs the
/// `keychain-access-groups` entitlement (SECURITY.md D8).
///
/// `swift test` has no entitlement, so this type is compiled there but only its
/// queries are checked; storing and reading are tested by the app-hosted tests.
struct KeychainItemStore: SecureItemStore {
    /// nil: the app's default group, the first in its `keychain-access-groups`.
    let accessGroup: String?

    init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
    }

    func add(_ data: Data, as item: StoredItem, protection: ItemProtection) throws {
        let query = try addQuery(data, as: item, protection: protection)
        let status = SecItemAdd(query as CFDictionary, nil)
        switch status {
        case errSecSuccess: return
        case errSecDuplicateItem: throw SecureStoreError.duplicateItem
        default: throw Self.error(for: status)
        }
    }

    func replace(_ data: Data, for item: StoredItem) throws -> Bool {
        let changes = [kSecValueData as String: data] as CFDictionary
        let status = SecItemUpdate(baseQuery(item) as CFDictionary, changes)
        switch status {
        case errSecSuccess: return true
        case errSecItemNotFound: return false
        default: throw Self.error(for: status)
        }
    }

    func copy(_ item: StoredItem) throws -> Data? {
        var query = baseQuery(item)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw SecureStoreError.unavailable }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw Self.error(for: status)
        }
    }

    func delete(_ item: StoredItem) throws {
        let status = SecItemDelete(baseQuery(item) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.error(for: status)
        }
    }

    func accounts(in collection: StoredItem.Collection) throws -> [String] {
        var query = commonAttributes(service: collection.rawValue)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            let items = result as? [[String: Any]] ?? []
            return items.compactMap { $0[kSecAttrAccount as String] as? String }
        case errSecItemNotFound:
            return []
        default:
            throw Self.error(for: status)
        }
    }

    // MARK: Queries (checked by unit tests)

    func commonAttributes(service: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            // The iOS-style Keychain: access groups and access control, instead of
            // the legacy file-based macOS keychain with its per-app ACL prompts.
            kSecUseDataProtectionKeychain as String: true,
            // Never iCloud Keychain: private keys and trust decisions stay on this Mac.
            kSecAttrSynchronizable as String: false,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    func baseQuery(_ item: StoredItem) -> [String: Any] {
        var query = commonAttributes(service: item.collection.rawValue)
        query[kSecAttrAccount as String] = item.account
        return query
    }

    func addQuery(_ data: Data, as item: StoredItem, protection: ItemProtection) throws -> [String: Any] {
        var query = baseQuery(item)
        query[kSecValueData as String] = data
        switch protection {
        case .userPresence:
            // Accessibility and access control together: readable only while unlocked,
            // on this device, and only after Touch ID or the login password.
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error)
            else {
                _ = error?.takeRetainedValue()
                throw SecureStoreError.unavailable
            }
            query[kSecAttrAccessControl as String] = access
        case .whenUnlocked:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        return query
    }

    private static func error(for status: OSStatus) -> SecureStoreError {
        if status == errSecUserCanceled { return .cancelled }
        DebugLog.record(keychainStatus: status)
        return .unavailable
    }
}
#endif
