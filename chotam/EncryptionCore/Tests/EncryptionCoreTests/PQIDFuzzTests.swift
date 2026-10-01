import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import EncryptionCore

/// The `.pqid` parser must reject hostile input by throwing, never by trapping. As
/// with the header fuzzer, "the test finishes" is the property under test, and every
/// input is seeded so a failure is reproducible.
final class PQIDFuzzTests: XCTestCase {
    /// Every entry point. Anything thrown must be a `CoreFailure`; anything that
    /// parses must be a well-formed identity.
    private func exercise(_ bytes: [UInt8], file: StaticString = #filePath, line: UInt = #line) {
        do {
            let identity = try PQIDCodec.decode(bytes)
            XCTAssertEqual(identity.encoded, bytes, file: file, line: line)
        } catch is CoreFailure {
        } catch {
            XCTFail("non-CoreFailure error \(type(of: error))", file: file, line: line)
        }
        do {
            _ = try PublicIdentity(importing: Data(bytes))
        } catch {
            // Typed throws: always an IdentityError.
        }
    }

    private func exercise(string: String, file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try PQIDCodec.decode(string: string)
        } catch is CoreFailure {
        } catch {
            XCTFail("non-CoreFailure error \(type(of: error))", file: file, line: line)
        }
    }

    func testRandomBytes() {
        var rng = SeededGenerator(seed: 0x9_1D)
        for _ in 0 ..< 100_000 {
            exercise(rng.bytes(Int(rng.next() % 400)))
        }
    }

    /// Random bodies behind a valid magic and version, at and around the real sizes,
    /// with the length fields sometimes set right so the parser gets further in.
    func testRandomBytesBehindValidPrelude() {
        var rng = SeededGenerator(seed: 0xCAFE)
        let prelude = Array("CHOTAMID".utf8) + [0x00, 0x01]
        for i in 0 ..< 3_000 {
            let target = IdentityFormat.pqidFixedSize + Int(rng.next() % 65)
            let jitter = i % 5 == 0 ? Int(rng.next() % 7) - 3 : 0
            var bytes = prelude + rng.bytes(max(0, target - prelude.count + jitter))
            if bytes.count >= 12, rng.next() % 2 == 0 { bytes.put(UInt16(1216), at: 10) }
            if bytes.count >= 1230, rng.next() % 2 == 0 { bytes.put(UInt16(1952), at: 1228) }
            if bytes.count >= 3184, rng.next() % 2 == 0 { bytes.put(UInt16(32), at: 3182) }
            if bytes.count >= 3218, rng.next() % 2 == 0 { bytes[3216] = 1; bytes[3217] = UInt8(rng.next() % 2) }
            if bytes.count >= 3235, rng.next() % 2 == 0 {
                bytes.put(UInt64(3 + rng.next() % 14), at: 3218)
                bytes.put(UInt64(256 << 20), at: 3226)
                bytes[3234] = 1
            }
            if bytes.count > 3251, rng.next() % 2 == 0 { bytes[3251] = UInt8(rng.next() % 70) }
            exercise(bytes)
        }
    }

    func testTruncationsAndExtensionsOfGoldenFile() throws {
        let golden = try IdentityVectors.pqid()
        var rng = SeededGenerator(seed: 0x7E)
        for _ in 0 ..< 1_000 {
            exercise(Array(golden.prefix(Int(rng.next() % UInt64(golden.count)))))
            exercise(golden + rng.bytes(1 + Int(rng.next() % 2_000)))
        }
    }

    /// Bit flips anywhere in a valid file. Most reach the signature check; none may
    /// crash, and none may parse (every byte is covered by a check or the signature).
    func testBitFlipsNeverParse() throws {
        let golden = try IdentityVectors.pqid()
        var rng = SeededGenerator(seed: 0xF11B)
        for _ in 0 ..< 3_000 {
            var bytes = golden
            for _ in 0 ..< Int(1 + rng.next() % 3) {
                let bit = Int(rng.next() % UInt64(bytes.count * 8))
                bytes[bit / 8] ^= 1 << UInt8(bit % 8)
            }
            guard bytes != golden else { continue }
            XCTAssertThrowsError(try PQIDCodec.decode(bytes))
        }
    }

    func testRandomStrings() throws {
        var rng = SeededGenerator(seed: 0x5_7121)
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \n-_*é")
        for _ in 0 ..< 20_000 {
            let length = Int(rng.next() % 200)
            exercise(string: String((0 ..< length).map { _ in alphabet[Int(rng.next() % UInt64(alphabet.count))] }))
        }
        // Valid Base64 of random bytes, so decoding succeeds and the bytes reach the parser.
        for _ in 0 ..< 5_000 {
            exercise(string: Data(rng.bytes(Int(rng.next() % 300))).base64EncodedString())
        }
        // Base64 of damaged golden files.
        let golden = try IdentityVectors.pqid()
        for _ in 0 ..< 300 {
            var bytes = golden
            bytes[Int(rng.next() % UInt64(bytes.count))] ^= UInt8(1 + rng.next() % 255)
            exercise(string: Data(bytes).base64EncodedString())
        }
    }

    /// The contacts file wraps .pqid files inside AES-GCM. Its parser gets the same
    /// treatment: hostile bytes, truncations and flips, with the right key and the
    /// wrong one.
    func testContactsFileParserNeverTraps() throws {
        var rng = SeededGenerator(seed: 0x2EC)
        let key = SymmetricKey(size: .bits256)
        let owner = KeyID(bytes: Array(repeating: 7, count: 32))
        let contacts = try (0 ..< 3).map { i in
            Contact(name: "Contact \(i)", isVerified: i == 0, publicIdentity: try SomeoneElse().publicIdentity)
        }
        let file = try ContactsFile.encode(contacts, owner: owner, key: key)
        XCTAssertEqual(try ContactsFile.decode(file, owner: owner, key: key), contacts)

        for length in stride(from: 0, to: file.count, by: 11) {
            XCTAssertThrowsError(try ContactsFile.decode(Array(file.prefix(length)), owner: owner, key: key))
        }
        for _ in 0 ..< 500 {
            var bytes = file
            bytes[Int(rng.next() % UInt64(bytes.count))] ^= UInt8(1 + rng.next() % 255)
            XCTAssertThrowsError(try ContactsFile.decode(bytes, owner: owner, key: key))
        }
        for _ in 0 ..< 20_000 {
            let bytes = rng.bytes(Int(rng.next() % 200))
            XCTAssertThrowsError(try ContactsFile.decode(bytes, owner: owner, key: key))
        }
        // Authenticated plaintexts of any shape, so the inner parser sees them too.
        for _ in 0 ..< 2_000 {
            let plaintext = rng.bytes(Int(rng.next() % 300))
            let nonce = rng.bytes(12)
            let header = Array("CHOTAMCF".utf8) + [0, 1] + owner.bytes + nonce
            let box = try AES.GCM.seal(plaintext, using: key, nonce: try AES.GCM.Nonce(data: nonce), authenticating: header)
            let bytes = header + [UInt8](box.ciphertext) + [UInt8](box.tag)
            do {
                _ = try ContactsFile.decode(bytes, owner: owner, key: key)
            } catch is CoreFailure {
            } catch {
                XCTFail("non-CoreFailure error \(type(of: error))")
            }
        }
    }
}
