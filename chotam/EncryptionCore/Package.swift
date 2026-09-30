// swift-tools-version: 6.2
import PackageDescription

// Crypto provider
// - Apple platforms: the system CryptoKit framework. No package dependency at all.
// - Linux: apple/swift-crypto (Apple's open-source implementation of the CryptoKit
//   API) so the core can be built and unit-tested in a Linux container.
//   It is declared inside `#if os(Linux)`, so when this manifest is evaluated on
//   macOS it is never resolved, fetched or linked. Versions are pinned exactly.
var packageDependencies: [Package.Dependency] = []
var coreDependencies: [Target.Dependency] = []
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
        .target(name: "EncryptionCore", dependencies: coreDependencies),
        .testTarget(name: "EncryptionCoreTests", dependencies: testDependencies),
    ],
    swiftLanguageModes: [.v6]
)
