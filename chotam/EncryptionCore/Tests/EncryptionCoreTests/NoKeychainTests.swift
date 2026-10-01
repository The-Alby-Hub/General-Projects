import Foundation
import XCTest

/// Frozen rule (SECURITY.md D18): Chotam never touches the macOS Keychain or the
/// Secure Enclave, now or in any later phase. This scans every source file of the
/// package for the APIs that would, so the rule can't be broken unnoticed.
final class NoKeychainTests: XCTestCase {
    /// Keychain, Secure Enclave and Touch ID APIs, and the Keychain wrapper libraries.
    static let forbidden = [
        "SecItemAdd", "SecItemCopyMatching", "SecItemUpdate", "SecItemDelete", "SecKeychain",
        "kSecClass", "kSecAttr", "kSecValue", "kSecReturn", "kSecMatch", "kSecUse",
        "SecAccessControl", "SecureEnclave", "kSecAttrTokenIDSecureEnclave",
        "LAContext", "LocalAuthentication", "import Security",
        "KeychainAccess", "Valet", "SAMKeychain", "UICKeyChainStore", "keychain-access-groups",
    ]

    func testNoKeychainAPIsInSources() throws {
        // This file is Tests/EncryptionCoreTests/NoKeychainTests.swift; the package is two levels up.
        let package = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let sources = package.appendingPathComponent("Sources", isDirectory: true)
        var scanned = 0
        var violations: [String] = []
        let walker = try XCTUnwrap(FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil))
        for case let url as URL in walker where ["swift", "h", "c", "m", "plist", "entitlements"].contains(url.pathExtension) {
            let text = try String(contentsOf: url, encoding: .utf8)
            scanned += 1
            for token in Self.forbidden where text.contains(token) {
                violations.append("\(url.lastPathComponent): \(token)")
            }
        }
        XCTAssertGreaterThan(scanned, 30, "the scan must actually find the sources")
        XCTAssertEqual(violations, [], "Keychain or Secure Enclave API in the sources (SECURITY.md D18)")
    }

    /// The manifest declares no dependency beyond the approved ones.
    func testManifestDependencies() throws {
        let package = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let manifest = try String(contentsOf: package.appendingPathComponent("Package.swift"), encoding: .utf8)
        let urls = manifest.components(separatedBy: "url: \"").dropFirst().map { $0.prefix { $0 != "\"" } }
        XCTAssertEqual(Set(urls.map(String.init)), [
            "https://github.com/jedisct1/swift-sodium.git",
            "https://github.com/apple/swift-crypto.git",  // Linux only
            "https://github.com/apple/swift-asn1.git",  // Linux only
        ])
    }
}
