// swift-tools-version: 6.2
import PackageDescription

// The app's view models and all of its testable logic (SECURITY.md D27).
//
// Foundation and Observation only: no SwiftUI, no AppKit, and never CryptoKit or
// libsodium. Everything cryptographic goes through EncryptionCore's public API. The
// SwiftUI views and AppKit glue live in ../App/Chotam and only call this module.
//
// No dependency beyond the local EncryptionCore package (checked by NoKeychainTests).
let package = Package(
    name: "ChotamAppModel",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "ChotamAppModel", targets: ["ChotamAppModel"]),
    ],
    dependencies: [
        .package(path: "../EncryptionCore"),
    ],
    targets: [
        .target(
            name: "ChotamAppModel",
            dependencies: [.product(name: "EncryptionCore", package: "EncryptionCore")]
        ),
        .testTarget(
            name: "ChotamAppModelTests",
            dependencies: ["ChotamAppModel", .product(name: "EncryptionCore", package: "EncryptionCore")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
