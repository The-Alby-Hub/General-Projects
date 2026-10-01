import Foundation
import XCTest
@testable import EncryptionCore

/// Golden recipient-mode files from `Vectors/make_recipient_vectors.py`, an independent
/// implementation of FORMAT.md §6: HPKE (RFC 9180) base mode and X-Wing
/// (draft-connolly-cfrg-xwing-kem-06) written from the specs and checked against their
/// published test vectors, ML-KEM-768 from kyber-py and OpenSSL, ML-DSA-65 from
/// dilithium-py and OpenSSL, Ed25519 from pyca/cryptography. See FORMAT.md §8.
///
/// Swift opens them with the golden identities, rebuilt from their passphrases. If
/// CryptoKit's X-Wing or HPKE ever differed from the drafts, these would fail.
final class RecipientGoldenTests: XCTestCase {
    enum Bob {
        /// Seven distinct EFF words (lines 200, 1300, 2400, 3500, 4600, 5700, 6800).
        static let passphrase = "angrily copy excretion joyride perish scouting tipped"
        static let file = "identity-bob-v1.pqid"
        static let size = 6632
        static let sha256 = "8cac900b2ffb3c1162064543690426adaf983969f0aadd04e508abc040788f0f"
        static let fingerprint = "KYVS TWF6 1AFH B7H7 2J9D MM1B VYCG MJ1A"
        static let encryptionKeyID = "4c2072ed26b99aff222a574009b173407c0e89e5849f142d3b0903c8cda69c1a"
        static let signingKeyID = "7294d21b83a43861a72c13e5d14007c629879124c86f57a9b4c596148968a44e"
    }

    enum Files {
        static let fromAlice = "recipients-from-alice.enc"
        static let fromAliceSize = 5973
        static let fromAliceSHA256 = "1a803e8e3c6393140b2ab41ff4af5e0b326b071df6bc98734b68ae2d8746bcb3"
        static let fromAlicePlaintext = Array("Chotam golden vector: recipient mode.\n".utf8)
        static let fromBob = "recipients-from-bob.enc"
        static let fromBobSize = 71575
        static let fromBobSHA256 = "d8e9b35554c894e7e7a6f7900bfe30866fb4858bf483e6196ed84b1b02a1ba21"
        static let fromBobPlaintext: [UInt8] = (0 ..< 65634).map { UInt8($0 % 251) }
    }

    private var vaults: [TestVault] = []

    override func tearDown() {
        vaults = []
        super.tearDown()
    }

    /// The golden identity rebuilt from its passphrase in a fresh vault, as on a new Mac.
    private func restore(_ pqid: String, passphrase: String) throws -> Identity {
        let vault = try TestVault()
        vaults.append(vault)
        return try vault.vault.restore(
            try PublicIdentity(importing: Data(try vector(pqid))), passphrase: passphrase)
    }

    private func alice() throws -> Identity {
        try restore(IdentityVectors.pqidFile, passphrase: IdentityVectors.typedPassphrase)
    }

    private func bob() throws -> Identity {
        try restore(Bob.file, passphrase: Bob.passphrase)
    }

    // MARK: Files

    func testGoldenFilesAreThePublishedOnes() throws {
        let bobPQID = try vector(Bob.file)
        XCTAssertEqual(bobPQID.count, Bob.size)
        XCTAssertEqual(sha256Hex(bobPQID), Bob.sha256)
        let fromAlice = try vector(Files.fromAlice)
        XCTAssertEqual(fromAlice.count, Files.fromAliceSize)
        XCTAssertEqual(sha256Hex(fromAlice), Files.fromAliceSHA256)
        let fromBob = try vector(Files.fromBob)
        XCTAssertEqual(fromBob.count, Files.fromBobSize)
        XCTAssertEqual(sha256Hex(fromBob), Files.fromBobSHA256)
    }

    func testBobsIdentityVector() throws {
        let identity = try PublicIdentity(importing: Data(try vector(Bob.file)))
        XCTAssertEqual(identity.fingerprint.description, Bob.fingerprint)
        XCTAssertEqual(identity.encryptionKeyID.hex, Bob.encryptionKeyID)
        XCTAssertEqual(identity.signingKeyID.hex, Bob.signingKeyID)
        XCTAssertEqual(identity.suggestedName, "Bob")
        // And the passphrase rebuilds exactly these keys.
        XCTAssertEqual(try bob().publicIdentity, identity)
    }

    /// The header layout an independent writer produced: two stanzas, the contact
    /// (Bob) first, the sender (Alice) last, Alice's signing key as the sender.
    func testGoldenHeaderLayout() throws {
        let (header, raw, parameters) = try recipientHeader(try vector(Files.fromAlice))
        XCTAssertEqual(raw.count, FormatV1.recipientHeaderLength(count: 2))
        XCTAssertEqual(parameters.stanzas.map { hexString($0.keyID) }, [Bob.encryptionKeyID, IdentityVectors.encryptionKeyID])
        XCTAssertEqual(hexString(parameters.senderKeyID), IdentityVectors.signingKeyID)
        XCTAssertEqual(header.hkdfSalt, Array(UInt8(0x60) ... UInt8(0x7F)))
        XCTAssertEqual(header.baseNonce, Array(UInt8(0x80) ... UInt8(0x8B)))
    }

    // MARK: Opening

    /// Alice opens the file she sent (her own stanza, encrypt to self): no contacts needed.
    func testAliceOpensHerOwnGoldenFile() throws {
        let opened = try recipientOpen(try vector(Files.fromAlice), as: try alice())
        XCTAssertEqual(opened.plaintext, Files.fromAlicePlaintext)
        XCTAssertEqual(opened.filename, "vector.txt")
        XCTAssertEqual(opened.signer, .you)
    }

    /// Bob's file: refused until Bob is a contact, then unverified, then verified.
    func testAliceOpensBobsGoldenFileOnceBobIsAContact() throws {
        let alice = try alice()
        let file = try vector(Files.fromBob)
        assertRecipientFailure(.unknownSender, file, as: alice)

        let bob = try alice.importContact(PublicIdentity(importing: Data(try vector(Bob.file))), name: "Bob")
        let opened = try recipientOpen(file, as: alice)
        XCTAssertEqual(opened.plaintext, Files.fromBobPlaintext)
        XCTAssertNil(opened.filename)
        XCTAssertEqual(opened.signer, .unverifiedContact(bob))

        let verified = try alice.markVerified(bob)
        XCTAssertEqual(try recipientOpen(file, as: alice).signer, .verifiedContact(verified))
    }

    /// Bob's side: his X-Wing key unwraps both files too.
    func testBobOpensBothGoldenFiles() throws {
        let bob = try bob()
        let alice = try bob.importContact(PublicIdentity(importing: Data(try vector(IdentityVectors.pqidFile))), name: "Alice")
        let fromAlice = try recipientOpen(try vector(Files.fromAlice), as: bob)
        XCTAssertEqual(fromAlice.plaintext, Files.fromAlicePlaintext)
        XCTAssertEqual(fromAlice.signer, .unverifiedContact(alice))
        let fromBob = try recipientOpen(try vector(Files.fromBob), as: bob)
        XCTAssertEqual(fromBob.plaintext, Files.fromBobPlaintext)
        XCTAssertEqual(fromBob.signer, .you)
    }

    func testGoldenFileThroughThePublicAPI() throws {
        let alice = try alice()
        _ = try alice.markVerified(try alice.importContact(PublicIdentity(importing: Data(try vector(Bob.file))), name: "Bob"))
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write(try vector(Files.fromAlice), to: Files.fromAlice)
        let result = try FileProcessor.decrypt(input, to: .folder(s.folder), using: .identity(alice))
        XCTAssertEqual(result.url.lastPathComponent, "vector.txt")
        XCTAssertEqual(result.signer, .you)
        XCTAssertEqual(try readFile(result.url), Files.fromAlicePlaintext)

        let fromBob = try s.write(try vector(Files.fromBob), to: Files.fromBob)
        let second = try FileProcessor.decrypt(fromBob, to: .file(s.url("bob.bin")), using: .identity(alice))
        guard case .verifiedContact(let contact)? = second.signer else { return XCTFail("expected a verified contact") }
        XCTAssertEqual(contact.name, "Bob")
        XCTAssertEqual(try readFile(second.url), Files.fromBobPlaintext)
    }

    /// A single flipped bit anywhere in a golden file stops it.
    func testTamperedGoldenFilesFail() throws {
        let alice = try alice()
        _ = try alice.importContact(PublicIdentity(importing: Data(try vector(Bob.file))), name: "Bob")
        let file = try vector(Files.fromBob)
        for offset in [20, 200, 3000, file.count - 4000, file.count - 3373 - 1, file.count - 1] {
            var tampered = file
            tampered[offset] ^= 0x80
            let written = MemorySink()
            XCTAssertThrowsError(try recipientOpen(tampered, as: alice, written: written), "byte \(offset)") {
                XCTAssertEqual(FileProcessor.decryptionError(for: $0), .failed, "byte \(offset)")
            }
            XCTAssertEqual(written.bytes, [], "byte \(offset)")
        }
    }
}
