import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// Recipient mode (FORMAT.md §6, SECURITY.md D19–D22): HPKE X-Wing wrapping, hybrid
/// signatures, two-pass decryption, signers, and the public API around them.
///
/// Identities are real (derived at the cheapest KDF cost in temp vaults); outsiders who
/// never need an identity of their own are `SomeoneElse`, with freshly generated keys.
final class RecipientModeTests: XCTestCase {
    private let c = Fixtures.chunk
    private let trailer = RecipientMode.trailerSize

    // MARK: Helpers

    /// Alice and Bob, each a verified contact of the other.
    private func aliceAndBob() throws -> (alice: Person, bob: Person, bobAtAlice: Contact, aliceAtBob: Contact) {
        let alice = try Person("Alice")
        let bob = try Person("Bob")
        let bobAtAlice = try alice.add(bob)
        let aliceAtBob = try bob.add(alice)
        return (alice, bob, bobAtAlice, aliceAtBob)
    }

    private func decryptError(_ body: () throws(DecryptionError) -> DecryptedFile) -> DecryptionError? {
        do {
            _ = try body()
            return nil
        } catch {
            return error
        }
    }

    private func encryptError(_ body: () throws(EncryptionError) -> URL) -> EncryptionError? {
        do {
            _ = try body()
            return nil
        } catch {
            return error
        }
    }

    /// Every temp file is gone, and so is the private folder it was made in.
    private func assertCleanedUp(_ probe: OutputProbe, file: StaticString = #filePath, line: UInt = #line) {
        for temp in probe.tempFiles {
            XCTAssertFalse(fileExists(temp), "temp file left behind", file: file, line: line)
            if !temp.lastPathComponent.hasPrefix(".") {
                XCTAssertFalse(
                    fileExists(temp.deletingLastPathComponent()), "temp folder left behind", file: file, line: line)
            }
        }
    }

    /// Fails with any internal reason, maps to the generic public error, and writes nothing.
    private func assertRejected(
        _ file: [UInt8], as identity: Identity, _ message: String = "",
        sourceFile: StaticString = #filePath, line: UInt = #line
    ) {
        let written = MemorySink()
        do {
            _ = try recipientOpen(file, as: identity, written: written)
            XCTFail("expected a failure \(message)", file: sourceFile, line: line)
        } catch {
            XCTAssertEqual(FileProcessor.decryptionError(for: error), .failed, message, file: sourceFile, line: line)
        }
        XCTAssertEqual(written.bytes, [], "plaintext written \(message)", file: sourceFile, line: line)
    }

    private func flipped(_ bytes: [UInt8], at offset: Int) -> [UInt8] {
        var copy = bytes
        copy[offset] ^= 0x01
        return copy
    }

    // MARK: Round trips

    /// "file.bin" makes a 10-byte metadata record, so `c - 10` and `2c - 10` fill exactly
    /// one and two chunks. The recipient and the sender (encrypt to self) both open it.
    func testRoundTripsAndTheSenderOpensWhatTheySent() throws {
        let (alice, bob, bobAtAlice, aliceAtBob) = try aliceAndBob()
        let headerLength = FormatV1.recipientHeaderLength(count: 2)
        for (size, chunks) in [(0, 1), (1, 1), (c - 10, 1), (c - 9, 2), (2 * c - 10, 2), (3 * c + 7, 4)] {
            let plaintext = Fixtures.pattern(size, seed: UInt64(size) &+ 3)
            let file = try recipientSeal(plaintext, from: alice, to: [bobAtAlice])
            XCTAssertEqual(file.count, headerLength + size + 10 + 16 * chunks + trailer, "size \(size)")

            let atBob = try recipientOpen(file, as: bob.identity)
            XCTAssertEqual(atBob.plaintext, plaintext, "size \(size)")
            XCTAssertEqual(atBob.filename, "file.bin")
            XCTAssertEqual(atBob.signer, .verifiedContact(aliceAtBob))
            XCTAssertTrue(atBob.signer.isVerified)

            let atAlice = try recipientOpen(file, as: alice.identity)
            XCTAssertEqual(atAlice.plaintext, plaintext, "size \(size)")
            XCTAssertEqual(atAlice.signer, .you)
        }
    }

    /// > 100 MB, through a real file. Both passes stream: no read asks for more than a
    /// sealed chunk plus the trailer plus one byte, and the file is read exactly twice.
    func testLargeFileStreamsThroughBothPasses() throws {
        let (alice, bob, bobAtAlice, _) = try aliceAndBob()
        let s = try Scratch()
        defer { s.remove() }
        let encrypted = s.url("large.bin.enc")
        let size = 100 * (1 << 20) + 1

        XCTAssertTrue(FileManager.default.createFile(atPath: encrypted.path, contents: nil))
        let writer = try FileHandle(forWritingTo: encrypted)
        let plain = CountingSource(PatternSource(count: size))
        let checked = try RecipientMode.check(try confirmedList([bobAtAlice]), signedBy: alice.identity)
        try RecipientMode.encrypt(to: checked, filename: "large.bin", from: plain, to: FileHandleSink(writer))
        try writer.close()
        XCTAssertEqual(plain.bytesRead, size)
        XCTAssertLessThanOrEqual(plain.largestRequest, FormatV1.chunkSize)

        let stream = size + 2 + 9  // + the metadata record for "large.bin"
        let chunks = (stream + c - 1) / c
        let fileSize = FormatV1.recipientHeaderLength(count: 2) + stream + 16 * chunks + trailer

        let reader = try FileHandle(forReadingFrom: encrypted)
        defer { try? reader.close() }
        let source = CountingRewindableSource(FileHandleSource(reader))
        let output = DigestSink()
        let opened = try RecipientMode.open(with: bob.identity, from: source, to: output)
        XCTAssertEqual(opened.filename, "large.bin")
        XCTAssertEqual(opened.signer, .verifiedContact(try bob.contact(alice.publicIdentity)))
        XCTAssertEqual(source.bytesRead, 2 * fileSize, "read exactly twice")
        XCTAssertLessThanOrEqual(source.largestRequest, FormatV1.sealedChunkSize + trailer + 1)
        XCTAssertEqual(output.count, size)
        XCTAssertEqual(output.finalize(), try PatternSource.digest(count: size))
    }

    // MARK: Who can open it

    func testOutsidersAndWrongKeysCantOpen() throws {
        let (alice, bob, bobAtAlice, _) = try aliceAndBob()
        let carol = try Person("Carol")
        try carol.add(alice)
        let file = try recipientSeal(Fixtures.pattern(500), from: alice, to: [bobAtAlice])

        // Not a recipient: stopped by key ID, before the signature or any key.
        assertRecipientFailure(.notARecipient, file, as: carol.identity)

        // A wrong private key: Bob's stanza only opens with Bob's X-Wing key.
        let (_, raw, parameters) = try recipientHeader(file)
        let bobStanza = try XCTUnwrap(parameters.stanzas.first { $0.keyID == bob.publicIdentity.encryptionKeyID.bytes })
        let context = try RecipientMode.wrapContext(rawHeader: raw)
        XCTAssertNoThrow(try bob.identity.withKeys { try RecipientMode.unwrap(bobStanza, context: context, with: $0.xwing) })
        assertCoreFailure(.unwrapFailed) {
            _ = try carol.identity.withKeys { try RecipientMode.unwrap(bobStanza, context: context, with: $0.xwing) }
        }
        assertCoreFailure(.unwrapFailed) {
            _ = try alice.identity.withKeys { try RecipientMode.unwrap(bobStanza, context: context, with: $0.xwing) }
        }
        // The right key with the wrong wrap context (FORMAT.md §6.2) fails too.
        assertCoreFailure(.unwrapFailed) {
            _ = try bob.identity.withKeys {
                try RecipientMode.unwrap(bobStanza, context: [UInt8](repeating: 0, count: 32), with: $0.xwing)
            }
        }
    }

    func testEveryRecipientOpensAndOutsidersDont() throws {
        let alice = try Person("Alice")
        let bob = try Person("Bob")
        let carol = try Person("Carol")
        let dave = try Person("Dave")
        let bobAtAlice = try alice.add(bob)
        let carolAtAlice = try alice.add(carol, verified: false)
        try bob.add(alice)
        try carol.add(alice, verified: false)
        try dave.add(alice)

        let plaintext = Fixtures.pattern(2 * c + 99)
        let file = try recipientSeal(plaintext, from: alice, to: [bobAtAlice, carolAtAlice])
        XCTAssertEqual(try recipientHeader(file).parameters.stanzas.count, 3)

        XCTAssertEqual(try recipientOpen(file, as: bob.identity).signer, .verifiedContact(try bob.contact(alice.publicIdentity)))
        XCTAssertEqual(
            try recipientOpen(file, as: carol.identity).signer, .unverifiedContact(try carol.contact(alice.publicIdentity)))
        XCTAssertFalse(try recipientOpen(file, as: carol.identity).signer.isVerified)
        for person in [alice, bob, carol] {
            XCTAssertEqual(try recipientOpen(file, as: person.identity).plaintext, plaintext, person.identity.name)
        }
        assertRecipientFailure(.notARecipient, file, as: dave.identity)
    }

    /// 63 contacts plus you: the largest header v1 allows (77,182 bytes).
    func testSixtyFourStanzaHeader() throws {
        let alice = try Person("Alice")
        var outsiders: [SomeoneElse] = []
        var contacts: [Contact] = []
        for index in 0 ..< FormatV1.maxContactRecipients {
            let outsider = try SomeoneElse(name: "C\(index)")
            outsiders.append(outsider)
            contacts.append(try alice.add(outsider.publicIdentity, name: "Contact \(index)"))
        }
        let plaintext = Fixtures.pattern(3000)
        let file = try recipientSeal(plaintext, from: alice, to: contacts)
        let (header, raw, parameters) = try recipientHeader(file)
        XCTAssertEqual(parameters.stanzas.count, 64)
        XCTAssertEqual(raw.count, 77_182)
        XCTAssertEqual(try recipientOpen(file, as: alice.identity).plaintext, plaintext)

        // Every contact's stanza unwraps, with their own key, to the Data Key this header
        // commits to.
        let context = try RecipientMode.wrapContext(rawHeader: raw)
        for outsider in outsiders {
            let stanza = try XCTUnwrap(parameters.stanzas.first { $0.keyID == outsider.publicIdentity.encryptionKeyID.bytes })
            let dataKey = try RecipientMode.unwrap(stanza, context: context, with: outsider.xwing)
            XCTAssertEqual(try KeySchedule.derive(ikm: dataKey, hkdfSalt: header.hkdfSalt).commitment, header.commitment)
        }

        // A 64th contact doesn't fit: the 64th stanza is always yours.
        let extra = try alice.add(try SomeoneElse(name: "Extra").publicIdentity, name: "Extra")
        XCTAssertThrowsError(try RecipientList(contacts + [extra])) {
            XCTAssertEqual($0 as? RecipientSelectionError, .tooManyRecipients)
        }
        XCTAssertThrowsError(
            try rawRecipientSeal(
                plaintext, sender: alice.publicIdentity, sign: alice.sign,
                to: (contacts + [extra]).map(\.publicIdentity))
        ) {
            XCTAssertEqual(($0 as? CoreFailure)?.reason, .recipientCountOutOfRange)
        }
    }

    /// Contacts' stanzas in key-ID order (nothing about how they were picked), yours last.
    func testStanzasAreSortedByKeyIDWithTheSenderLast() throws {
        let alice = try Person("Alice")
        var contacts: [Contact] = []
        for index in 0 ..< 5 {
            contacts.append(try alice.add(try SomeoneElse(name: "C\(index)").publicIdentity, name: "Contact \(index)"))
        }
        let file = try recipientSeal([1, 2, 3], from: alice, to: contacts.reversed())
        let parameters = try recipientHeader(file).parameters
        let ids = parameters.stanzas.map(\.keyID)
        XCTAssertEqual(ids.last, alice.publicIdentity.encryptionKeyID.bytes)
        let contactIDs = Array(ids.dropLast())
        XCTAssertEqual(contactIDs, contactIDs.sorted { $0.lexicographicallyPrecedes($1) })
        XCTAssertEqual(Set(contactIDs), Set(contacts.map(\.publicIdentity.encryptionKeyID.bytes)))
        XCTAssertEqual(parameters.senderKeyID, alice.publicIdentity.signingKeyID.bytes)
    }

    // MARK: Tampering

    func testTamperingIsRejectedAndWritesNothing() throws {
        let (alice, bob, bobAtAlice, _) = try aliceAndBob()
        let plaintext = Fixtures.pattern(3 * c + 5)
        let file = try recipientSeal(plaintext, from: alice, to: [bobAtAlice])
        let headerLength = FormatV1.recipientHeaderLength(count: 2)
        let sealed = FormatV1.sealedChunkSize
        XCTAssertEqual(try recipientOpen(file, as: bob.identity).plaintext, plaintext)

        // Header: every field is covered by the signature, checked before any key is used.
        for offset in [
            HeaderOffsets.hkdfSalt, HeaderOffsets.baseNonce + 5, HeaderOffsets.commitment + 31,
            stanzaOffset(0) + 2, stanzaOffset(0) + 40, stanzaOffset(0) + 1200,
            stanzaOffset(1) + 3, stanzaOffset(1) + 100, stanzaOffset(1) + 1203,
        ] {
            let tampered = flipped(file, at: offset)
            // Flipping Bob's own key ID makes the file "not for Bob"; anything else, a bad signature.
            let bobsKeyIDRange = try recipientHeader(file).parameters.stanzas.firstIndex {
                $0.keyID == bob.publicIdentity.encryptionKeyID.bytes
            }.map { stanzaOffset($0) ..< stanzaOffset($0) + 32 }
            let expected: CoreFailure.Reason = bobsKeyIDRange?.contains(offset) == true ? .notARecipient : .badSignature
            assertRecipientFailure(expected, tampered, as: bob.identity, "header byte \(offset)")
        }
        // Structural header fields are refused by the parser.
        for offset in [HeaderOffsets.version + 1, HeaderOffsets.mode, HeaderOffsets.headerLength + 3, HeaderOffsets.chunkSize + 2, HeaderOffsets.recipientCount] {
            assertRejected(flipped(file, at: offset), as: bob.identity, "header byte \(offset)")
        }
        // A changed sender key ID names nobody Bob knows: the distinct "unknown sender".
        assertRecipientFailure(.unknownSender, flipped(file, at: HeaderOffsets.modeParameters + 7), as: bob.identity)

        // Body: the first chunk, the middle, the final chunk's tag.
        for offset in [headerLength, headerLength + sealed + 17, file.count - trailer - 1] {
            assertRecipientFailure(.badSignature, flipped(file, at: offset), as: bob.identity, "body byte \(offset)")
        }
        // Trailer: both halves.
        for offset in [0, 63, 64, 1000, trailer - 1] {
            assertRecipientFailure(
                .badSignature, flipped(file, at: file.count - trailer + offset), as: bob.identity, "trailer byte \(offset)")
        }

        // Reordered chunks: swap chunks 0 and 1.
        var reordered = file
        let chunk0 = headerLength ..< headerLength + sealed
        let chunk1 = headerLength + sealed ..< headerLength + 2 * sealed
        reordered.replaceSubrange(chunk0, with: file[chunk1])
        reordered.replaceSubrange(chunk1, with: file[chunk0])
        assertRecipientFailure(.badSignature, reordered, as: bob.identity, "reordered")

        // Truncation: a byte, a whole chunk from the middle, everything after chunk 0.
        assertRejected(Array(file.dropLast()), as: bob.identity, "last byte dropped")
        var withoutChunk1 = file
        withoutChunk1.removeSubrange(chunk1)
        assertRecipientFailure(.badSignature, withoutChunk1, as: bob.identity, "chunk removed")
        assertRejected(Array(file.prefix(headerLength + sealed)), as: bob.identity, "only chunk 0")
        assertRejected(Array(file.prefix(headerLength)), as: bob.identity, "header only")

        // Appended bytes.
        assertRecipientFailure(.badSignature, file + [0], as: bob.identity, "one byte appended")
        assertRejected(file + file.suffix(trailer), as: bob.identity, "trailer appended twice")
    }

    // MARK: Signatures

    func testUnknownSignerIsRefusedDistinctly() throws {
        let alice = try Person("Alice")
        let mallory = try SomeoneElse(name: "Mallory")
        let plaintext = Fixtures.pattern(700)
        let file = try rawRecipientSeal(
            plaintext, sender: mallory.publicIdentity, sign: mallory.sign, to: [alice.publicIdentity])
        // Correctly signed, and for Alice, but by someone she doesn't know.
        assertRecipientFailure(.unknownSender, file, as: alice.identity)

        // Once imported (always unverified) the same file opens, reported as unverified.
        let imported = try alice.add(mallory.publicIdentity, name: "Mallory", verified: false)
        let opened = try recipientOpen(file, as: alice.identity)
        XCTAssertEqual(opened.plaintext, plaintext)
        XCTAssertEqual(opened.signer, .unverifiedContact(imported))
        let verified = try alice.identity.markVerified(imported)
        XCTAssertEqual(try recipientOpen(file, as: alice.identity).signer, .verifiedContact(verified))

        // Removed again: refused again (contacts are read when the file is opened).
        try alice.identity.remove(verified)
        assertRecipientFailure(.unknownSender, file, as: alice.identity)

        // Not for you *and* from an unknown sender: "not for you" wins.
        let stranger = try SomeoneElse(name: "Stranger")
        let notMine = try rawRecipientSeal(
            plaintext, sender: stranger.publicIdentity, sign: stranger.sign, to: [mallory.publicIdentity])
        assertRecipientFailure(.notARecipient, notMine, as: alice.identity)
    }

    func testForgedAndMismatchedSignaturesAreRejected() throws {
        let (alice, bob, _, aliceAtBob) = try aliceAndBob()
        let mallory = try SomeoneElse(name: "Mallory")
        let plaintext = Fixtures.pattern(5000)

        // A file naming Bob as its sender but signed by Mallory.
        let forged = try rawRecipientSeal(plaintext, sender: bob.publicIdentity, sign: mallory.sign, to: [alice.publicIdentity])
        assertRecipientFailure(.badSignature, forged, as: alice.identity)

        let genuine = try recipientSeal(plaintext, from: bob, to: [aliceAtBob])
        let other = try recipientSeal(Fixtures.pattern(5000, seed: 9), from: bob, to: [aliceAtBob])
        XCTAssertEqual(try recipientOpen(genuine, as: alice.identity).plaintext, plaintext)

        // Stripped signature.
        assertRejected(Array(genuine.dropLast(trailer)), as: alice.identity, "stripped")
        // Bob's genuine signature from a different file.
        assertRecipientFailure(
            .badSignature, Array(genuine.dropLast(trailer)) + other.suffix(trailer), as: alice.identity, "other file's signature")
        // Each half is required: a valid half from this file with the other half from another.
        let ed = RecipientMode.trailerSize - FormatV1.mldsa65SignatureSize
        let ownEd = Array(genuine.suffix(trailer).prefix(ed))
        let ownML = Array(genuine.suffix(FormatV1.mldsa65SignatureSize))
        let otherEd = Array(other.suffix(trailer).prefix(ed))
        let otherML = Array(other.suffix(FormatV1.mldsa65SignatureSize))
        let body = Array(genuine.dropLast(trailer))
        assertRecipientFailure(.badSignature, body + ownEd + otherML, as: alice.identity, "ML-DSA half broken")
        assertRecipientFailure(.badSignature, body + otherEd + ownML, as: alice.identity, "Ed25519 half broken")
        assertRecipientFailure(.badSignature, body + [UInt8](repeating: 0, count: ed) + ownML, as: alice.identity, "Ed25519 zeroed")
        assertRecipientFailure(
            .badSignature, body + ownEd + [UInt8](repeating: 0, count: FormatV1.mldsa65SignatureSize), as: alice.identity,
            "ML-DSA zeroed")
    }

    /// A stanza lifted from another file to the same recipient, even re-signed by the
    /// real sender, doesn't unwrap: the wrap context binds it to its own header.
    func testStanzaMovedFromAnotherFileDoesNotUnwrap() throws {
        let (alice, bob, bobAtAlice, _) = try aliceAndBob()
        let a = try recipientSeal(Fixtures.pattern(800), from: alice, to: [bobAtAlice])
        let b = try recipientSeal(Fixtures.pattern(800, seed: 2), from: alice, to: [bobAtAlice])
        let index = try XCTUnwrap(try recipientHeader(a).parameters.stanzas.firstIndex {
            $0.keyID == bob.publicIdentity.encryptionKeyID.bytes
        })
        let range = stanzaOffset(index) ..< stanzaOffset(index + 1)
        var moved = a
        moved.replaceSubrange(range, with: b[range])
        assertRecipientFailure(.badSignature, moved, as: bob.identity, "not re-signed")
        assertRecipientFailure(.unwrapFailed, try resign(moved, with: alice.sign), as: bob.identity, "re-signed")
        // Control: re-signing an untouched file changes nothing.
        XCTAssertEqual(try recipientOpen(try resign(a, with: alice.sign), as: bob.identity).plaintext, Fixtures.pattern(800))
    }

    // MARK: Key commitment

    /// A validly signed file whose header commits to a different key: rejected after
    /// unwrapping, before a single chunk is opened, and nothing is written.
    func testCommitmentMismatchIsRejectedBeforeAnyChunkIsOpened() throws {
        let (alice, bob, _, _) = try aliceAndBob()
        let plaintext = Fixtures.pattern(2 * c + 1)
        let crafted = try rawRecipientSeal(
            plaintext, sender: alice.publicIdentity, sign: alice.sign, to: [bob.publicIdentity],
            options: .init(commitment: [UInt8](repeating: 0x5A, count: 32)))
        var opened = 0
        let written = MemorySink()
        XCTAssertThrowsError(try recipientOpen(crafted, as: bob.identity, written: written, onChunkOpen: { opened += 1 })) {
            XCTAssertEqual(($0 as? CoreFailure)?.reason, .commitmentMismatch)
        }
        XCTAssertEqual(opened, 0, "no chunk may be opened")
        XCTAssertEqual(written.bytes, [])

        // Control: the same path with the real commitment opens every chunk.
        let honest = try rawRecipientSeal(plaintext, sender: alice.publicIdentity, sign: alice.sign, to: [bob.publicIdentity])
        XCTAssertEqual(try recipientOpen(honest, as: bob.identity, onChunkOpen: { opened += 1 }).plaintext, plaintext)
        XCTAssertEqual(opened, 3)
    }

    // MARK: Two passes

    /// A file that changes between pass 1 and pass 2 fails in pass 2.
    func testFileChangedBetweenPassesFails() throws {
        let (alice, bob, bobAtAlice, _) = try aliceAndBob()
        let file = try recipientSeal(Fixtures.pattern(2 * c + 1), from: alice, to: [bobAtAlice])
        let another = try recipientSeal(Fixtures.pattern(2 * c + 1), from: alice, to: [bobAtAlice])
        let cases: [([UInt8], CoreFailure.Reason, String)] = [
            (another, .changedBetweenPasses, "a different header"),
            (flipped(file, at: file.count - trailer - 1), .chunkAuthenticationFailed, "a changed chunk"),
            (flipped(file, at: file.count - 1), .changedBetweenPasses, "a changed trailer"),
            (Array(file.dropLast(trailer)) + another.suffix(trailer), .changedBetweenPasses, "a swapped trailer"),
        ]
        for (second, reason, label) in cases {
            XCTAssertThrowsError(
                try RecipientMode.open(with: bob.identity, from: ChangingSource(first: file, second: second), to: MemorySink()),
                label
            ) {
                XCTAssertEqual(($0 as? CoreFailure)?.reason, reason, label)
            }
        }
        // Control: unchanged, it opens.
        XCTAssertNoThrow(try RecipientMode.open(with: bob.identity, from: ChangingSource(first: file, second: file), to: MemorySink()))
    }

    /// The same through real files: the file on disk is changed right after pass 1.
    /// Decryption fails and nothing is left behind, temp file included.
    func testFileChangedOnDiskBetweenPassesLeavesNothing() throws {
        let (alice, bob, bobAtAlice, _) = try aliceAndBob()
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write(Fixtures.pattern(3 * c + 50), to: "Report.pdf")
        let encrypted = try FileProcessor.encrypt(
            input, to: .folder(s.folder), using: .recipients(try RecipientList([bobAtAlice]), signedBy: alice.identity))
        let original = try readFile(encrypted)
        let size = original.count
        let out = try s.makeFolder("out")

        let changes: [(String, (FileHandle) throws -> Void)] = [
            ("flip the last body byte", { handle in
                try handle.seek(toOffset: UInt64(size - self.trailer - 1))
                try handle.write(contentsOf: [original[size - self.trailer - 1] ^ 0x01])
            }),
            ("truncate the trailer", { handle in try handle.truncate(atOffset: UInt64(size - 10)) }),
            ("append a byte", { handle in
                try handle.seekToEnd()
                try handle.write(contentsOf: [0])
            }),
        ]
        for (label, change) in changes {
            try Data(original).write(to: encrypted)
            var changed = false
            let probe = OutputProbe()
            let hook = ProgressHook(report: { completed, _ in
                guard !changed, completed >= Int64(size), let handle = try? FileHandle(forUpdating: encrypted) else { return }
                changed = true
                try? change(handle)
                try? handle.close()
            })
            let error = decryptError {
                try FileProcessor.decrypt(
                    encrypted, to: .folder(out), using: .identity(bob.identity), hooks: probe.hooks, progress: hook)
            }
            XCTAssertTrue(changed, label)
            XCTAssertEqual(error, .failed, label)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: out.path), [], label)
            assertCleanedUp(probe)
        }
    }

    // MARK: The public API

    func testPublicAPIRoundTripReportsTheSigner() throws {
        let (alice, bob, bobAtAlice, aliceAtBob) = try aliceAndBob()
        let s = try Scratch()
        defer { s.remove() }
        let contents = Fixtures.pattern(2 * c + 3)
        let input = try s.write(contents, to: "Report.pdf")
        let probe = OutputProbe()

        let encrypted = try FileProcessor.encrypt(
            input, to: .folder(s.folder), using: .recipients(try RecipientList([bobAtAlice]), signedBy: alice.identity),
            hooks: probe.hooks)
        XCTAssertEqual(encrypted.lastPathComponent, "Report.pdf.enc")
        XCTAssertEqual(try permissions(encrypted), 0o600)
        assertCleanedUp(probe)

        let out = try s.makeFolder("out")
        let atBob = try FileProcessor.decrypt(encrypted, to: .folder(out), using: .identity(bob.identity))
        XCTAssertEqual(atBob.url.lastPathComponent, "Report.pdf")
        XCTAssertEqual(atBob.storedFilename, "Report.pdf")
        XCTAssertEqual(atBob.signer, .verifiedContact(aliceAtBob))
        XCTAssertEqual(try readFile(atBob.url), contents)
        XCTAssertEqual(try permissions(atBob.url), 0o600)

        let atAlice = try FileProcessor.decrypt(encrypted, to: .file(s.url("mine.pdf")), using: .identity(alice.identity))
        XCTAssertEqual(atAlice.signer, .you)
        XCTAssertEqual(try readFile(atAlice.url), contents)

        // Password mode reports no signer.
        let passwordFile = try FileProcessor.encrypt(
            input, to: .file(s.url("p.enc")), using: .password(PasswordFixtures.password, cost: PasswordFixtures.fast))
        let viaPassword = try FileProcessor.decrypt(
            passwordFile, to: .file(s.url("p.pdf")), using: .password(PasswordFixtures.password))
        XCTAssertNil(viaPassword.signer)
        // A password-mode file isn't a recipient-mode file, and vice versa.
        XCTAssertEqual(decryptError { try FileProcessor.decrypt(passwordFile, to: .folder(out), using: .identity(bob.identity)) }, .failed)
        XCTAssertEqual(decryptError { try FileProcessor.decrypt(encrypted, to: .folder(out), using: .password(PasswordFixtures.password)) }, .failed)
    }

    /// Forged, unknown-sender and not-for-you files: the right public error, and nothing
    /// on disk afterwards.
    func testNothingIsWrittenForARejectedFile() throws {
        let (alice, bob, _, _) = try aliceAndBob()
        let mallory = try SomeoneElse(name: "Mallory")
        let carol = try Person("Carol")
        let s = try Scratch()
        defer { s.remove() }
        let plaintext = Fixtures.pattern(3 * c)

        let forged = try s.write(
            try rawRecipientSeal(plaintext, sender: bob.publicIdentity, sign: mallory.sign, to: [alice.publicIdentity]),
            to: "forged.enc")
        let unknown = try s.write(
            try rawRecipientSeal(plaintext, sender: mallory.publicIdentity, sign: mallory.sign, to: [alice.publicIdentity]),
            to: "unknown.enc")
        let notMine = try s.write(
            try rawRecipientSeal(plaintext, sender: bob.publicIdentity, sign: bob.sign, to: [carol.publicIdentity]),
            to: "not-mine.enc")

        let before = try s.snapshot()
        for (url, expected) in [(forged, DecryptionError.failed), (unknown, .unknownSender), (notMine, .failed)] {
            let probe = OutputProbe()
            XCTAssertEqual(
                decryptError {
                    try FileProcessor.decrypt(url, to: .folder(s.folder), using: .identity(alice.identity), hooks: probe.hooks)
                },
                expected, url.lastPathComponent)
            XCTAssertEqual(probe.tempFiles, [], "no temp file is even created before pass 2")
            XCTAssertEqual(try s.snapshot(), before, url.lastPathComponent)
        }
    }

    func testLockedIdentityFailsCleanly() throws {
        let (alice, bob, bobAtAlice, _) = try aliceAndBob()
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write(Fixtures.pattern(1000), to: "Report.pdf")
        let list = try RecipientList([bobAtAlice])
        let encrypted = try FileProcessor.encrypt(input, to: .folder(s.folder), using: .recipients(list, signedBy: alice.identity))
        let before = try s.snapshot()

        alice.identity.lock()
        bob.identity.lock()
        XCTAssertEqual(
            encryptError { try FileProcessor.encrypt(input, to: .file(s.url("x.enc")), using: .recipients(list, signedBy: alice.identity)) },
            .identity(.locked))
        XCTAssertEqual(
            decryptError { try FileProcessor.decrypt(encrypted, to: .folder(s.folder), using: .identity(bob.identity)) },
            .identity(.locked))
        XCTAssertEqual(try s.snapshot(), before)
        XCTAssertThrowsError(try recipientOpen(try readFile(encrypted), as: bob.identity)) {
            XCTAssertEqual($0 as? IdentityError, .locked)
        }
    }

    /// Locked while working: the signature is made last, and the Data Key is unwrapped
    /// only after pass 1, so both fail cleanly part-way through.
    func testIdentityLockedPartWayLeavesNothing() throws {
        let (alice, bob, bobAtAlice, _) = try aliceAndBob()
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write(Fixtures.pattern(4 * c), to: "Report.pdf")
        let list = try RecipientList([bobAtAlice])
        let encrypted = try FileProcessor.encrypt(input, to: .folder(s.folder), using: .recipients(list, signedBy: alice.identity))
        let before = try s.snapshot()

        let decryptProbe = OutputProbe()
        let lockBob = ProgressHook(report: { completed, total in
            if completed >= total / 4 { bob.identity.lock() }
        })
        XCTAssertEqual(
            decryptError {
                try FileProcessor.decrypt(
                    encrypted, to: .folder(s.folder), using: .identity(bob.identity), hooks: decryptProbe.hooks,
                    progress: lockBob)
            },
            .identity(.locked))
        XCTAssertEqual(decryptProbe.tempFiles, [])

        let encryptProbe = OutputProbe()
        let lockAlice = ProgressHook(report: { completed, total in
            if completed >= total / 2 { alice.identity.lock() }
        })
        XCTAssertEqual(
            encryptError {
                try FileProcessor.encrypt(
                    input, to: .file(s.url("x.enc")), using: .recipients(list, signedBy: alice.identity),
                    hooks: encryptProbe.hooks, progress: lockAlice)
            },
            .identity(.locked))
        XCTAssertFalse(encryptProbe.tempFiles.isEmpty, "the ciphertext was being written")
        assertCleanedUp(encryptProbe)
        XCTAssertEqual(try s.snapshot(), before)
    }

    func testRecipientsMustStillBeContactsOfTheSigner() throws {
        let alice = try Person("Alice")
        let bob = try Person("Bob")
        let carol = try Person("Carol")
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write([1, 2, 3], to: "a.txt")
        let before = try s.snapshot()
        func attempt(_ list: RecipientList) -> EncryptionError? {
            encryptError { try FileProcessor.encrypt(input, to: .folder(s.folder), using: .recipients(list, signedBy: alice.identity)) }
        }

        // Removed after the list was made.
        let bobAtAlice = try alice.add(bob)
        let list = try RecipientList([bobAtAlice])
        try alice.identity.remove(bobAtAlice)
        XCTAssertEqual(attempt(list), .recipientsChanged)

        // A list made from another identity's contacts.
        let carolAtBob = try bob.add(carol)
        XCTAssertEqual(attempt(try RecipientList([carolAtBob])), .recipientsChanged)
        // Even one naming the signer themself.
        let aliceAtBob = try bob.add(alice)
        XCTAssertEqual(attempt(try RecipientList([aliceAtBob])), .recipientsChanged)
        XCTAssertEqual(try s.snapshot(), before)

        // Re-imported, it works again.
        let again = try alice.add(bob)
        XCTAssertNil(attempt(try RecipientList([again])))
    }

    func testUnverifiedRecipientsStillNeedConfirmation() throws {
        let alice = try Person("Alice")
        let bob = try Person("Bob")
        let bobAtAlice = try alice.add(bob, verified: false)
        try bob.add(alice)
        XCTAssertThrowsError(try RecipientList([bobAtAlice])) { error in
            guard case .needsConfirmation(let request)? = error as? RecipientSelectionError else {
                return XCTFail("expected needsConfirmation")
            }
            XCTAssertEqual(request.unverifiedContacts, [bobAtAlice])
        }
        // Only the confirmed list encrypts.
        let file = try recipientSeal([4, 5, 6], from: alice, to: [bobAtAlice])
        XCTAssertEqual(try recipientOpen(file, as: bob.identity).plaintext, [4, 5, 6])
    }

    // MARK: Errors and descriptions

    func testRecipientErrorMapping() {
        XCTAssertEqual(FileProcessor.decryptionError(for: CoreFailure(.unknownSender)), .unknownSender)
        XCTAssertEqual(FileProcessor.decryptionError(for: CoreFailure(.cancelled)), .cancelled)
        for reason: CoreFailure.Reason in [.notARecipient, .badSignature, .unwrapFailed, .changedBetweenPasses, .commitmentMismatch] {
            XCTAssertEqual(FileProcessor.decryptionError(for: CoreFailure(reason)), .failed, reason.rawValue)
        }
        for problem: IdentityError in [.locked, .contactsDamaged, .storageFailed] {
            XCTAssertEqual(FileProcessor.decryptionError(for: problem), .identity(problem))
            XCTAssertEqual(FileProcessor.encryptionError(for: problem), .identity(problem))
        }
        XCTAssertEqual(FileProcessor.encryptionError(for: CoreFailure(.recipientsChanged)), .recipientsChanged)
        XCTAssertEqual(FileProcessor.encryptionError(for: CoreFailure(.cancelled)), .cancelled)

        let decryption: [DecryptionError] = [.failed, .notEnoughMemory, .unknownSender, .identity(.locked), .cancelled]
        let encryption: [EncryptionError] = [.weakPassword, .invalidFilename, .notEnoughMemory, .identity(.locked), .recipientsChanged, .cancelled, .unexpected]
        let messages = decryption.map(\.errorDescription) + encryption.map(\.errorDescription)
        XCTAssertFalse(messages.contains(nil))
        XCTAssertEqual(Set(messages).count, messages.count)
        XCTAssertEqual(DecryptionError.identity(.locked).errorDescription, IdentityError.locked.errorDescription)
    }

    func testModesDontDescribeKeysOrNames() throws {
        let (alice, _, bobAtAlice, _) = try aliceAndBob()
        let texts = [
            String(describing: EncryptionMode.recipients(try RecipientList([bobAtAlice]), signedBy: alice.identity)),
            String(reflecting: EncryptionMode.recipients(try RecipientList([bobAtAlice]), signedBy: alice.identity)),
            String(describing: DecryptionMode.identity(alice.identity)),
            String(reflecting: DecryptionMode.identity(alice.identity)),
        ]
        for text in texts {
            XCTAssertFalse(text.contains("Alice") || text.contains("Bob"), text)
            XCTAssertFalse(text.contains(alice.identity.fingerprint.description), text)
        }
    }
}
