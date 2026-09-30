#if canImport(Security) && canImport(CryptoKit)
import CryptoKit
import Foundation
import Security
import XCTest
@testable import EncryptionCore

/// What `swift test` can check about the real Keychain and Secure Enclave without the
/// `keychain-access-groups` entitlement (SECURITY.md D8): the exact query attributes,
/// and, if this Mac allows it, an ML-DSA-65 key in the Secure Enclave. Nothing here
/// writes to the Keychain or shows a prompt.
final class KeychainQueryTests: XCTestCase {
    private let store = KeychainItemStore(accessGroup: "TEAMID.app.chotam")

    func testCommonAttributes() {
        let query = store.baseQuery(.encryptionKey)
        XCTAssertEqual(query[kSecClass as String] as? String, kSecClassGenericPassword as String)
        XCTAssertEqual(query[kSecAttrService as String] as? String, "app.chotam.identity")
        XCTAssertEqual(query[kSecAttrAccount as String] as? String, "encryption")
        XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertEqual(query[kSecAttrSynchronizable as String] as? Bool, false)
        XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, "TEAMID.app.chotam")
    }

    func testPrivateKeyItemsNeedUserPresence() throws {
        let query = try store.addQuery(Data([1]), as: .encryptionKey, protection: .userPresence)
        XCTAssertNotNil(query[kSecAttrAccessControl as String])
        // Accessibility is inside the access control object; setting both is an error.
        XCTAssertNil(query[kSecAttrAccessible as String])
        XCTAssertEqual(query[kSecValueData as String] as? Data, Data([1]))
    }

    func testPublicItemsAreThisDeviceOnly() throws {
        let query = try store.addQuery(Data([1]), as: .ownIdentity, protection: .whenUnlocked)
        XCTAssertEqual(
            query[kSecAttrAccessible as String] as? String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        XCTAssertNil(query[kSecAttrAccessControl as String])
    }

    func testContactItemsLiveInTheirOwnService() {
        let identity = try! PQIDCodec.decode(try! IdentityVectors.pqid())
        let query = store.baseQuery(.contact(identity.encryptionKeyID))
        XCTAssertEqual(query[kSecAttrService as String] as? String, "app.chotam.contacts")
        XCTAssertEqual(query[kSecAttrAccount as String] as? String, IdentityVectors.encryptionKeyID)
    }

    /// Tells us whether this Mac's Secure Enclave handles ML-DSA-65 at all. The key is
    /// made with `.privateKeyUsage` only (no user presence), so there is no prompt;
    /// Chotam's real keys also require user presence. Skipped where unsupported.
    func testSecureEnclaveMLDSA65WhenAvailable() throws {
        guard SecureEnclave.isAvailable else { throw XCTSkip("This Mac has no Secure Enclave.") }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error)
        else {
            _ = error?.takeRetainedValue()
            return XCTFail("SecAccessControlCreateWithFlags failed")
        }
        let key: SecureEnclave.MLDSA65.PrivateKey
        do {
            key = try SecureEnclave.MLDSA65.PrivateKey(accessControl: access)
        } catch {
            throw XCTSkip("The Secure Enclave can't create an ML-DSA-65 key here (\(error)); identities would use the Keychain fallback.")
        }
        let message = Data("Chotam".utf8)
        let signature = try key.signature(for: message)
        XCTAssertEqual(signature.count, FormatV1.mldsa65SignatureSize)
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: message))
        XCTAssertEqual(key.publicKey.rawRepresentation.count, IdentityFormat.mldsa65PublicKeySize)

        // The handle Chotam stores reopens the same key.
        let reopened = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: key.dataRepresentation)
        XCTAssertEqual(reopened.publicKey.rawRepresentation, key.publicKey.rawRepresentation)
    }
}
#endif
