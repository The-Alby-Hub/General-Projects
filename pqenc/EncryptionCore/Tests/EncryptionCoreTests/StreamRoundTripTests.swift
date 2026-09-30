import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

final class StreamRoundTripTests: XCTestCase {
    private let c = Fixtures.chunk

    private func assertRoundTrip(
        size: Int, filename: String? = "file.bin",
        parameters: FileHeader.ModeParameters = Fixtures.passwordParameters,
        file: StaticString = #filePath, line: UInt = #line
    ) throws {
        let ikm = Fixtures.randomKey()
        let plaintext = Fixtures.pattern(size, seed: UInt64(size))
        let sealed = try sealBytes(plaintext, ikm: ikm, filename: filename, parameters: parameters)

        // Size is fully determined by the format: header + stream + 16 bytes per chunk.
        let headerLength = Fixtures.header(parameters: parameters).encodedLength
        let streamLength = 2 + (filename?.utf8.count ?? 0) + size
        let chunks = max(1, (streamLength + c - 1) / c)
        XCTAssertEqual(sealed.count, headerLength + streamLength + chunks * 16, "size \(size)", file: file, line: line)

        let opened = try openBytes(sealed, ikm: ikm)
        XCTAssertEqual(opened.plaintext, plaintext, "size \(size)", file: file, line: line)
        XCTAssertEqual(opened.summary.filename, filename, file: file, line: line)
        XCTAssertEqual(opened.summary.chunkCount, UInt64(chunks), "size \(size)", file: file, line: line)
        XCTAssertEqual(opened.summary.trailer, [], file: file, line: line)
    }

    func testEmptyFile() throws { try assertRoundTrip(size: 0) }
    func testOneByteFile() throws { try assertRoundTrip(size: 1) }
    func testFileOfExactlyOneChunk() throws { try assertRoundTrip(size: c) }
    func testFileOfExactlyTwoChunks() throws { try assertRoundTrip(size: 2 * c) }
    func testMultiChunkFileWithPartialFinalChunk() throws { try assertRoundTrip(size: 3 * c + 17) }

    /// Metadata "file.bin" takes 10 bytes, so these sizes put the plaintext
    /// stream exactly on, one under and one over the chunk boundary.
    func testStreamOnChunkBoundary() throws {
        try assertRoundTrip(size: c - 10 - 1)
        try assertRoundTrip(size: c - 10)
        try assertRoundTrip(size: c - 10 + 1)
        try assertRoundTrip(size: 2 * c - 10)
        try assertRoundTrip(size: c - 2, filename: nil)
    }

    func testExactBoundaryHasNoEmptyTrailingChunk() throws {
        let ikm = Fixtures.randomKey()
        let sealed = try sealBytes(Fixtures.pattern(c - 2), ikm: ikm, filename: nil)
        XCTAssertEqual(sealed.count, FormatV1.passwordHeaderLength + Fixtures.sealedChunk)
        XCTAssertEqual(try openBytes(sealed, ikm: ikm).summary.chunkCount, 1)
    }

    func testFilenames() throws {
        try assertRoundTrip(size: 5, filename: nil)
        try assertRoundTrip(size: 5, filename: "Document.pdf")
        try assertRoundTrip(size: 5, filename: "résumé 📄 年度報告.pdf")
        try assertRoundTrip(size: 5, filename: String(repeating: "a", count: 1024))
        try assertRoundTrip(size: 5, filename: ".hidden")
    }

    func testInvalidFilenamesAreRejectedWhenSealing() {
        let bad = [
            "", ".", "..", "a/b", "/etc/passwd", "a\u{0}b", "line\nbreak", "tab\there",
            "invoice\u{202E}fdp.exe", "x\u{2066}y", "x\u{200F}y", "c1\u{85}control",
            String(repeating: "a", count: 1025),
            String(repeating: "é", count: 513),  // 1026 UTF-8 bytes
        ]
        for name in bad {
            assertCoreFailure(.invalidFilename, name.debugDescription) {
                _ = try sealBytes([1, 2, 3], ikm: Fixtures.randomKey(), filename: name)
            }
        }
    }

    func testMetadataDecoderRejectsMalformedRecords() {
        let cases: [[UInt8]] = [
            [],  // no length
            [0],  // half a length
            [0, 5, 0x61, 0x62],  // length longer than the data
            [0x04, 0x01] + [UInt8](repeating: 0x61, count: 1025),  // 1025 bytes
            [0, 2, 0xC3, 0x28],  // invalid UTF-8
            [0, 3, 0x61, 0x2F, 0x62],  // "a/b"
            [0, 2, 0x2E, 0x2E],  // ".."
            [0, 3, 0xE2, 0x80, 0xAE],  // U+202E alone
        ]
        for record in cases {
            assertCoreFailure(.malformedMetadata, "\(record.prefix(8))") { _ = try MetadataRecord.decode(record) }
        }
        XCTAssertEqual(try MetadataRecord.decode([0, 0, 9, 9]).contentOffset, 2)
    }

    func testRecipientModeHeaderAndTrailerHoldback() throws {
        // Phase 1 only frames the trailer; Phase 5 fills it with the signature.
        let ikm = Fixtures.randomKey()
        let parameters = Fixtures.recipientParameters(count: 3)
        let trailer = Fixtures.pattern(FormatV1.mldsa65SignatureSize, seed: 99)
        for size in [0, 1, c - 10, c, 2 * c + 5] {
            let plaintext = Fixtures.pattern(size)
            let sealed = try sealBytes(plaintext, ikm: ikm, parameters: parameters, trailer: trailer)
            let opened = try openBytes(sealed, ikm: ikm, trailerLength: trailer.count)
            XCTAssertEqual(opened.plaintext, plaintext, "size \(size)")
            XCTAssertEqual(opened.summary.trailer, trailer, "size \(size)")
        }
    }

    func testSealAndOpenReportTheSameDigests() throws {
        let ikm = Fixtures.randomKey()
        let sink = MemorySink()
        let sealSummary = try StreamSealer.seal(
            ikm: ikm, parameters: Fixtures.passwordParameters, filename: "x",
            from: MemorySource(Fixtures.pattern(3 * c)), to: sink)
        let opened = try openBytes(sink.bytes, ikm: ikm)
        XCTAssertEqual(opened.summary.headerHash, sealSummary.headerHash)
        XCTAssertEqual(opened.summary.ciphertextDigest, sealSummary.ciphertextDigest)
        XCTAssertEqual(opened.summary.chunkCount, sealSummary.chunkCount)
        XCTAssertEqual(sealSummary.headerHash, Array(SHA256.hash(data: sink.bytes.prefix(124))))
    }

    func testSameInputEncryptsDifferentlyEachTime() throws {
        let ikm = Fixtures.randomKey()
        let plaintext = Fixtures.pattern(1000)
        let a = try sealBytes(plaintext, ikm: ikm)
        let b = try sealBytes(plaintext, ikm: ikm)
        XCTAssertNotEqual(Array(a[16 ..< 92]), Array(b[16 ..< 92]), "salt, nonce and commitment must be fresh")
        XCTAssertNotEqual(Array(a[124...]), Array(b[124...]))
    }

    /// > 100 MB through real files, bounded memory: no read ever asks for more
    /// than one sealed chunk (+1 byte of lookahead).
    func testLargeFileRoundTripThroughFiles() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("pqenc-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let input = directory.appendingPathComponent("large.bin")
        let encrypted = directory.appendingPathComponent("large.bin.enc")
        let output = directory.appendingPathComponent("large.out")

        // 100 MiB + 1 byte, built from a 1 MiB block stamped with its index.
        let block = Fixtures.pattern(1 << 20, seed: 7)
        var inputHash = SHA256()
        XCTAssertTrue(FileManager.default.createFile(atPath: input.path, contents: nil))
        let writer = try FileHandle(forWritingTo: input)
        for i in 0 ..< 100 {
            var stamped = block
            stamped.put(UInt64(i), at: 0)
            inputHash.update(data: stamped)
            try writer.write(contentsOf: stamped)
        }
        try writer.write(contentsOf: [UInt8]([0x42]))
        inputHash.update(data: [UInt8]([0x42]))
        try writer.close()
        let totalSize = 100 * (1 << 20) + 1

        let ikm = Fixtures.randomKey()

        // Encrypt.
        let readIn = try FileHandle(forReadingFrom: input)
        XCTAssertTrue(FileManager.default.createFile(atPath: encrypted.path, contents: nil))
        let writeEnc = try FileHandle(forWritingTo: encrypted)
        let plainSource = CountingSource(FileHandleSource(readIn))
        let sealSummary = try StreamSealer.seal(
            ikm: ikm, parameters: Fixtures.passwordParameters, filename: "large.bin",
            from: plainSource, to: FileHandleSink(writeEnc))
        try readIn.close()
        try writeEnc.close()
        XCTAssertLessThanOrEqual(plainSource.largestRequest, FormatV1.chunkSize)

        let expectedChunks = (2 + 9 + totalSize + c - 1) / c
        XCTAssertEqual(sealSummary.chunkCount, UInt64(expectedChunks))
        let sizeProbe = try FileHandle(forReadingFrom: encrypted)
        let encryptedSize = try sizeProbe.seekToEnd()
        try sizeProbe.close()
        XCTAssertEqual(encryptedSize, UInt64(124 + 2 + 9 + totalSize + expectedChunks * 16))

        // Decrypt.
        let readEnc = try FileHandle(forReadingFrom: encrypted)
        XCTAssertTrue(FileManager.default.createFile(atPath: output.path, contents: nil))
        let writeOut = try FileHandle(forWritingTo: output)
        let encSource = CountingSource(FileHandleSource(readEnc))
        let (header, raw) = try HeaderCodec.read(from: encSource)
        let summary = try StreamOpener.open(
            ikm: ikm, header: header, rawHeader: raw, body: encSource,
            trailerLength: 0, to: FileHandleSink(writeOut))
        try readEnc.close()
        try writeOut.close()
        XCTAssertLessThanOrEqual(encSource.largestRequest, FormatV1.sealedChunkSize + 1)
        XCTAssertEqual(summary.filename, "large.bin")

        // Compare by streaming hash, never loading 100 MB at once.
        let readOut = try FileHandle(forReadingFrom: output)
        var outputHash = SHA256()
        var outputSize = 0
        while let data = try readOut.read(upToCount: 1 << 20), !data.isEmpty {
            outputHash.update(data: data)
            outputSize += data.count
        }
        try readOut.close()
        XCTAssertEqual(outputSize, totalSize)
        XCTAssertEqual(Array(outputHash.finalize()), Array(inputHash.finalize()))
    }
}
