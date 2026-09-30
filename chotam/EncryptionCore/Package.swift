// swift-tools-version: 6.2
import PackageDescription

// Crypto provider
// - Apple platforms: the system CryptoKit framework.
// - Linux: apple/swift-crypto (Apple's open-source implementation of the CryptoKit
//   API) so the core can be built and unit-tested in a Linux container.
//   It is declared inside `#if os(Linux)`, so when this manifest is evaluated on
//   macOS it is never resolved, fetched or linked. Versions are pinned exactly.
//
// Argon2id (password mode) comes from libsodium, the one third-party dependency the
// spec allows. swift-sodium is pinned exactly: tag 0.11.0 is commit
// cfd195c76882aa9b997560ca7cb95d72fbf5db00. Only its `Clibsodium` product (the C
// library) is used, never the `Sodium` Swift wrapper (SECURITY.md D11). On macOS it
// links the prebuilt static libsodium shipped in that repo; on Linux it needs the
// system package `libsodium-dev`.
var packageDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0"),
]
var coreDependencies: [Target.Dependency] = [
    .product(name: "Clibsodium", package: "swift-sodium"),
]
var testDependencies: [Target.Dependency] = ["EncryptionCore"]

#if os(Linux)
packageDependencies += [
    .package(url: "https://github.com/apple/swift-crypto.git", exact: "5.0.0"),
    // Transitive dependency of swift-crypto, pinned exactly as well.
    .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.3"),
]
coreDependencies += [.product(name: "Crypto", package: "swift-crypto")]
testDependencies += [
    .product(name: "Crypto", package: "swift-crypto"),
    // Listed only so the exact pin above is a used dependency (no SwiftPM warning).
    .product(name: "SwiftASN1", package: "swift-asn1"),
]
#endif

let package = Package(
    name: "EncryptionCore",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "EncryptionCore", targets: ["EncryptionCore"]),
    ],
    dependencies: packageDependencies,
    targets: [
        .target(
            name: "EncryptionCore",
            dependencies: coreDependencies,
            // EFF large wordlist (CC-BY 3.0 US), byte-identical to EFF's file.
            resources: [.copy("Resources/eff_large_wordlist.txt")]
        ),
        .testTarget(
            name: "EncryptionCoreTests",
            dependencies: testDependencies,
            // Golden files built by an independent implementation of FORMAT.md.
            // Read from disk by path, not bundled: a test target with its own
            // resources gets a second `Bundle.module`, which is ambiguous next to
            // `@testable import EncryptionCore`.
            exclude: ["Vectors"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
