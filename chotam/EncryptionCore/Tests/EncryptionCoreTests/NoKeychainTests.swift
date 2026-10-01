import Foundation
import XCTest

/// Frozen rule (SECURITY.md D18): Chotam never touches the macOS Keychain or the
/// Secure Enclave, now or in any later phase. This scans every source file of the
/// package, and of the app (Phase 6: `App/` and `AppModel/`, including the Xcode project
/// and the entitlements), for the APIs that would, so the rule can't be broken unnoticed.
final class NoKeychainTests: XCTestCase {
    /// `chotam/`: this file is chotam/EncryptionCore/Tests/EncryptionCoreTests/NoKeychainTests.swift.
    static let chotam = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent()

    /// Every scannable file under `folder`, and the forbidden tokens found in each.
    static func violations(in folder: URL) throws -> (scanned: Int, violations: [String]) {
        var scanned = 0
        var violations: [String] = []
        let walker = try XCTUnwrap(FileManager.default.enumerator(at: folder, includingPropertiesForKeys: nil))
        for case let url as URL in walker {
            // Build products and per-user Xcode state aren't sources.
            if ["build", "DerivedData", ".build", "xcuserdata"].contains(url.lastPathComponent) {
                walker.skipDescendants()
                continue
            }
            guard ["swift", "h", "c", "m", "plist", "entitlements", "pbxproj", "xcscheme", "xcconfig"]
                .contains(url.pathExtension)
            else { continue }
            let text = try String(contentsOf: url, encoding: .utf8)
            scanned += 1
            for token in forbidden where text.contains(token) {
                violations.append("\(url.lastPathComponent): \(token)")
            }
        }
        return (scanned, violations)
    }

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
        let (scanned, violations) = try Self.violations(in: package.appendingPathComponent("Sources", isDirectory: true))
        XCTAssertGreaterThan(scanned, 30, "the scan must actually find the sources")
        XCTAssertEqual(violations, [], "Keychain or Secure Enclave API in the sources (SECURITY.md D18)")
    }

    /// The app's sources, view models, project file and entitlements (Phase 6, D27).
    func testNoKeychainAPIsInTheApp() throws {
        let app = try Self.violations(in: Self.chotam.appendingPathComponent("App", isDirectory: true))
        let model = try Self.violations(in: Self.chotam.appendingPathComponent("AppModel/Sources", isDirectory: true))
        XCTAssertGreaterThan(app.scanned, 15, "the scan must find the app's sources, project and entitlements")
        XCTAssertGreaterThan(model.scanned, 5, "the scan must find the view models")
        XCTAssertEqual(app.violations + model.violations, [], "Keychain or Secure Enclave API in the app (SECURITY.md D18)")
    }

    /// The app's entitlements are exactly the two allowed (SECURITY.md D18, §8): no
    /// Keychain access group, no network, no get-task-allow, no bookmarks.
    func testAppEntitlementsAreExactlySandboxAndUserSelectedFiles() throws {
        let url = Self.chotam.appendingPathComponent("App/Config/Chotam.entitlements")
        let plist = try PropertyListSerialization.propertyList(from: try Data(contentsOf: url), format: nil)
        let entitlements = try XCTUnwrap(plist as? [String: Any])
        XCTAssertEqual(Set(entitlements.keys), [
            "com.apple.security.app-sandbox",
            "com.apple.security.files.user-selected.read-write",
        ])
        XCTAssertEqual(entitlements["com.apple.security.app-sandbox"] as? Bool, true)
        XCTAssertEqual(entitlements["com.apple.security.files.user-selected.read-write"] as? Bool, true)
    }

    /// The view-model package depends on nothing but the local core.
    func testAppModelManifestHasNoRemoteDependencies() throws {
        let manifest = try String(
            contentsOf: Self.chotam.appendingPathComponent("AppModel/Package.swift"), encoding: .utf8)
        XCTAssertFalse(manifest.contains("url:"), "no remote packages")
        XCTAssertTrue(manifest.contains(".package(path: \"../EncryptionCore\")"))
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
