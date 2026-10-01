import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Someone with a real, unlocked identity in their own temp vault (cheapest KDF cost),
/// for recipient-mode tests. Each one has a fresh random salt, so different keys.
final class Person {
    let vault: TestVault
    let identity: Identity

    init(_ name: String) throws {
        vault = try TestVault()
        identity = try vault.create(name: name)
    }

    var publicIdentity: PublicIdentity { identity.publicIdentity }

    /// Imports `other` as a contact, verified unless asked otherwise.
    @discardableResult
    func add(_ other: PublicIdentity, name: String, verified: Bool = true) throws -> Contact {
        let contact = try identity.importContact(other, name: name)
        return verified ? try identity.markVerified(contact) : contact
    }

    @discardableResult
    func add(_ other: Person, verified: Bool = true) throws -> Contact {
        try add(other.publicIdentity, name: other.identity.name, verified: verified)
    }

    /// The current contact record for `other`.
    func contact(_ other: PublicIdentity) throws -> Contact {
        try XCTUnwrap(try identity.contacts().first { $0.publicIdentity == other })
    }

    /// Signs like `EncryptionMode.recipients` does: with this identity's hybrid key.
    var sign: ([UInt8]) throws -> [UInt8] {
        let identity = self.identity
        return { message in
            try identity.withKeys { try HybridSignature.sign(message, ed25519: $0.ed25519, mldsa: $0.mldsa) }
        }
    }
}

extension SomeoneElse {
    /// Signs with this outsider's hybrid key.
    var sign: ([UInt8]) throws -> [UInt8] {
        let ed25519 = self.ed25519
        let mldsa = self.mldsa
        return { message in try HybridSignature.sign(message, ed25519: ed25519, mldsa: mldsa) }
    }
}

/// A recipient list, confirming unverified contacts as the app would after asking.
func confirmedList(_ contacts: [Contact]) throws -> RecipientList {
    do {
        return try RecipientList(contacts)
    } catch let error as RecipientSelectionError {
        if case .needsConfirmation(let request) = error {
            return request.confirm()
        }
        throw error
    }
}

/// Encrypts `plaintext` from `sender` to `contacts` (plus the sender) exactly as
/// `FileProcessor` does, in memory: checked recipients, signed at the end.
func recipientSeal(
    _ plaintext: [UInt8], from sender: Person, to contacts: [Contact], filename: String? = "file.bin"
) throws -> [UInt8] {
    let checked = try RecipientMode.check(try confirmedList(contacts), signedBy: sender.identity)
    let sink = MemorySink()
    try RecipientMode.encrypt(to: checked, filename: filename, from: MemorySource(plaintext), to: sink)
    return sink.bytes
}

/// The low-level sealer, for files `FileProcessor` would never make: any sender key,
/// any recipients, a forced commitment.
func rawRecipientSeal(
    _ plaintext: [UInt8], sender: PublicIdentity, sign: ([UInt8]) throws -> [UInt8],
    to contacts: [PublicIdentity], filename: String? = "file.bin",
    options: RecipientMode.SealOptions = RecipientMode.SealOptions()
) throws -> [UInt8] {
    let sink = MemorySink()
    try RecipientMode.seal(
        contacts: contacts, sender: sender, sign: sign, filename: filename,
        from: MemorySource(plaintext), to: sink, options: options)
    return sink.bytes
}

struct RecipientOpened {
    let plaintext: [UInt8]
    let filename: String?
    let signer: Signer
}

/// Opens recipient-mode bytes in memory, throwing the precise internal reason.
/// `written` receives everything that reached the sink, even on failure.
func recipientOpen(
    _ file: [UInt8], as identity: Identity, written: MemorySink = MemorySink(),
    onChunkOpen: (() -> Void)? = nil
) throws -> RecipientOpened {
    let opened = try RecipientMode.open(
        with: identity, from: MemorySource(file), to: written, onChunkOpen: onChunkOpen)
    return RecipientOpened(plaintext: written.bytes, filename: opened.filename, signer: opened.signer)
}

/// Asserts that opening fails with `expected` and that **nothing** reached the sink.
func assertRecipientFailure(
    _ expected: CoreFailure.Reason, _ file: [UInt8], as identity: Identity, _ message: String = "",
    sourceFile: StaticString = #filePath, line: UInt = #line
) {
    let written = MemorySink()
    do {
        _ = try recipientOpen(file, as: identity, written: written)
        XCTFail("expected \(expected.rawValue) \(message)", file: sourceFile, line: line)
    } catch let failure as CoreFailure {
        XCTAssertEqual(failure.reason, expected, message, file: sourceFile, line: line)
    } catch {
        XCTFail("unexpected error \(error) \(message)", file: sourceFile, line: line)
    }
    XCTAssertEqual(written.bytes, [], "plaintext written for a rejected file \(message)", file: sourceFile, line: line)
}

/// Recomputes the trailer over the file's current header and body, as its sender
/// (or a forger holding some key) would. Used to get tampered files past pass 1, so
/// the later checks (unwrap, commitment) are what's tested.
func resign(_ file: [UInt8], with sign: ([UInt8]) throws -> [UInt8]) throws -> [UInt8] {
    let source = MemorySource(file)
    let (_, raw) = try HeaderCodec.read(from: source)
    let body = try RecipientMode.digestBody(from: source)
    let message = RecipientMode.signedMessage(
        headerHash: Array(SHA256.hash(data: raw)), ciphertextDigest: body.ciphertextDigest, chunkCount: body.chunkCount)
    return Array(file.dropLast(RecipientMode.trailerSize)) + (try sign(message))
}

/// The parsed recipient header of a file.
func recipientHeader(_ file: [UInt8]) throws -> (header: FileHeader, raw: [UInt8], parameters: FileHeader.RecipientParameters) {
    let (header, raw) = try HeaderCodec.read(from: MemorySource(file))
    guard case .recipients(let parameters) = header.parameters else {
        throw CoreFailure(.wrongMode)
    }
    return (header, raw, parameters)
}

/// The byte offset of stanza `index` in a recipient header.
func stanzaOffset(_ index: Int) -> Int {
    FormatV1.recipientHeaderLength(count: 0) + index * FormatV1.recipientStanzaSize
}

/// A source that serves `first` until rewound, then `second`: a file that changes
/// between the two passes.
final class ChangingSource: RewindableSource {
    private var current: MemorySource
    private let second: [UInt8]

    init(first: [UInt8], second: [UInt8]) {
        current = MemorySource(first)
        self.second = second
    }

    func read(maxCount: Int) throws -> [UInt8] {
        try current.read(maxCount: maxCount)
    }

    func rewind() throws {
        current = MemorySource(second)
    }
}

/// Wraps a rewindable source and records the largest read request, to prove streaming.
final class CountingRewindableSource: RewindableSource {
    private let base: any RewindableSource
    private(set) var largestRequest = 0
    private(set) var bytesRead = 0

    init(_ base: any RewindableSource) {
        self.base = base
    }

    func read(maxCount: Int) throws -> [UInt8] {
        largestRequest = max(largestRequest, maxCount)
        let piece = try base.read(maxCount: maxCount)
        bytesRead += piece.count
        return piece
    }

    func rewind() throws {
        try base.rewind()
    }
}
