import Foundation
import XCTest

/// Rules about the app's code and build settings that would otherwise only be checked
/// by eye (SECURITY.md D27, D34, D35, §7.4, §8). The Keychain scan of these same files is
/// in EncryptionCore's NoKeychainTests.
final class ArchitectureTests: XCTestCase {
    /// `chotam/`: this file is chotam/AppModel/Tests/ChotamAppModelTests/ArchitectureTests.swift.
    private static let chotam = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent()

    private static func swiftFiles(in relativePath: String) throws -> [(name: String, text: String)] {
        let root = chotam.appendingPathComponent(relativePath, isDirectory: true)
        let walker = try XCTUnwrap(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil))
        var files: [(String, String)] = []
        for case let url as URL in walker where url.pathExtension == "swift" {
            files.append((url.lastPathComponent, try String(contentsOf: url, encoding: .utf8)))
        }
        return files
    }

    private static func text(_ relativePath: String) throws -> String {
        try String(contentsOf: chotam.appendingPathComponent(relativePath), encoding: .utf8)
    }

    private static func plist(_ relativePath: String) throws -> [String: Any] {
        let data = try Data(contentsOf: chotam.appendingPathComponent(relativePath))
        return try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    // MARK: Code

    /// The UI never touches CryptoKit or libsodium: only EncryptionCore's public API.
    func testAppNeverUsesCryptoDirectly() throws {
        let files = try Self.swiftFiles(in: "App/Chotam") + Self.swiftFiles(in: "AppModel/Sources")
        XCTAssertGreaterThan(files.count, 15, "the scan must find the app's sources")
        let forbidden = ["import CryptoKit", "import Crypto\n", "import Clibsodium", "import Sodium", "crypto_pwhash",
                         "@testable import"]
        for file in files {
            for token in forbidden {
                XCTAssertFalse(file.text.contains(token), "\(file.name) contains \(token)")
            }
        }
    }

    /// The view models are testable without a UI: Foundation and Observation only.
    func testAppModelImportsNoUIFramework() throws {
        for file in try Self.swiftFiles(in: "AppModel/Sources") {
            for token in ["import SwiftUI", "import AppKit", "import Cocoa", "import Combine"] {
                XCTAssertFalse(file.text.contains(token), "\(file.name) imports \(token)")
            }
        }
    }

    /// No logging beyond the core's fixed debug strings (SECURITY.md §7.4).
    func testNoLogging() throws {
        for file in try Self.swiftFiles(in: "App/Chotam") + Self.swiftFiles(in: "AppModel/Sources") {
            for token in ["print(", "NSLog(", "os_log(", "Logger(", "debugPrint(", "dump("] {
                XCTAssertFalse(file.text.contains(token), "\(file.name) contains \(token)")
            }
        }
    }

    /// The clipboard is used in exactly one place, for the public identity string; never
    /// for a passphrase or password (D34).
    func testClipboardOnlyForThePublicIdentity() throws {
        let users = try (Self.swiftFiles(in: "App/Chotam") + Self.swiftFiles(in: "AppModel/Sources"))
            .filter { $0.text.contains("NSPasteboard") || $0.text.contains("UIPasteboard") || $0.text.contains("pasteboard") }
            .map(\.name)
        XCTAssertEqual(users, ["PublicIdentityCopy.swift"])
    }

    /// `UserDefaults` holds only the idle timeout (D29), plus the volatile registration of
    /// `NSQuitAlwaysKeepsWindows = false`, which is never written to disk.
    func testUserDefaultsOnlyForTheIdleTimeout() throws {
        let users = try (Self.swiftFiles(in: "App/Chotam") + Self.swiftFiles(in: "AppModel/Sources"))
            .filter { $0.text.contains("UserDefaults") || $0.text.contains("@AppStorage") }
            .map(\.name).sorted()
        XCTAssertEqual(users, ["AppSession.swift", "AutoLock.swift", "ChotamApp.swift", "Hardening.swift"])
        XCTAssertFalse(try Self.text("App/Chotam/ChotamApp.swift").contains("@AppStorage"))
    }

    // MARK: Build settings

    func testInfoPlist() throws {
        let info = try Self.plist("App/Config/Info.plist")
        // One copy of Chotam at a time, so the temp sweep (D30) never sees a live file.
        XCTAssertEqual(info["LSMultipleInstancesProhibited"] as? Bool, true)
        // macOS must ask Chotam before quitting, so it locks and cleans up.
        XCTAssertEqual(info["NSSupportsSuddenTermination"] as? Bool, false)
        XCTAssertEqual(info["NSSupportsAutomaticTermination"] as? Bool, false)
        XCTAssertEqual(info["LSMinimumSystemVersion"] as? String, "$(MACOSX_DEPLOYMENT_TARGET)")
        // Nothing that would open a network or other system service.
        for key in info.keys {
            XCTAssertFalse(key.hasPrefix("NSAppTransport"), key)
            XCTAssertFalse(key.contains("UsageDescription"), "\(key): Chotam asks for no protected resource")
        }
    }

    func testProjectBuildSettings() throws {
        let project = try Self.text("App/Chotam.xcodeproj/project.pbxproj")
        XCTAssertEqual(project.components(separatedBy: "ENABLE_HARDENED_RUNTIME = YES;").count - 1, 2,
                       "hardened runtime in Debug and Release")
        XCTAssertEqual(project.components(separatedBy: "ENABLE_APP_SANDBOX = YES;").count - 1, 2)
        XCTAssertEqual(project.components(separatedBy: "CODE_SIGN_ENTITLEMENTS = Config/Chotam.entitlements;").count - 1, 2)
        XCTAssertEqual(project.components(separatedBy: "CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO;").count - 1, 1,
                       "Release builds get no get-task-allow (D35)")
        XCTAssertEqual(project.components(separatedBy: "MACOSX_DEPLOYMENT_TARGET = 26.0;").count - 1, 2,
                       "set once per configuration, at the project level")
        for forbidden in ["ENABLE_OUTGOING_NETWORK_CONNECTIONS = YES", "ENABLE_INCOMING_NETWORK_CONNECTIONS = YES",
                          "com.apple.security.get-task-allow", "XCRemoteSwiftPackageReference"] {
            XCTAssertFalse(project.contains(forbidden), forbidden)
        }
        XCTAssertTrue(project.contains("relativePath = ../EncryptionCore;"))
        XCTAssertTrue(project.contains("relativePath = ../AppModel;"))
    }
}
