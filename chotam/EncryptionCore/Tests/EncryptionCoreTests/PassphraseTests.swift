import Foundation
import XCTest
@testable import EncryptionCore

/// The bundled EFF wordlist.
final class WordlistTests: XCTestCase {
    func testBundledFileMatchesPinnedHash() throws {
        let data = try XCTUnwrap(Wordlist.bundledData(), "wordlist resource missing from the bundle")
        XCTAssertEqual(Wordlist.hexDigest(data), Wordlist.expectedSHA256)
        XCTAssertEqual(data.count, 108_800)
    }

    func testParsesAllWordsInDiceOrder() throws {
        let words = try XCTUnwrap(Wordlist.words)
        XCTAssertEqual(words.count, 7_776)
        XCTAssertEqual(Set(words).count, 7_776)
        XCTAssertEqual(words.first, "abacus")
        XCTAssertEqual(words[1], "abdomen")  // 11112
        XCTAssertEqual(words.last, "zoom")  // 66666
        XCTAssertEqual(words.map(\.count).min(), 3)
        XCTAssertEqual(words.map(\.count).max(), 9)
        XCTAssertEqual(Set(words.filter { $0.contains("-") }), ["drop-down", "felt-tip", "t-shirt", "yo-yo"])
        XCTAssertEqual(Wordlist.lookup?.count, 7_776)
    }

    func testDiceNumbers() {
        XCTAssertEqual(Wordlist.diceNumber(0), "11111")
        XCTAssertEqual(Wordlist.diceNumber(1), "11112")
        XCTAssertEqual(Wordlist.diceNumber(6), "11121")
        XCTAssertEqual(Wordlist.diceNumber(7_775), "66666")
    }

    /// Any change to the file, even one that still parses, disables the generator.
    func testEditedOrTruncatedFileIsRejected() throws {
        let data = try XCTUnwrap(Wordlist.bundledData())
        var edited = [UInt8](data)
        edited[6 + 4] = UInt8(ascii: "a")  // "abacus" → "abacas"
        XCTAssertNil(Wordlist.parse(Data(edited)))
        XCTAssertNil(Wordlist.parse(data.prefix(data.count - 1)))
        XCTAssertNil(Wordlist.parse(Data()))
        XCTAssertNotNil(Wordlist.parse(data))
    }
}

/// The passphrase generator.
final class PassphraseGeneratorTests: XCTestCase {
    func testDefaultIsSixDistinctEFFWordsSeparatedBySpaces() throws {
        let lookup = try XCTUnwrap(Wordlist.lookup)
        for _ in 0 ..< 50 {
            let passphrase = try PassphraseGenerator.generate()
            let words = passphrase.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
            XCTAssertEqual(words.count, 6, passphrase)
            XCTAssertEqual(Set(words).count, 6, passphrase)
            XCTAssertTrue(words.allSatisfy { lookup.contains($0) }, passphrase)
        }
    }

    func testWordCountRange() throws {
        XCTAssertEqual(try PassphraseGenerator.generate(wordCount: 10).split(separator: " ").count, 10)
        for bad in [-1, 0, 5, 11] {
            XCTAssertThrowsError(try PassphraseGenerator.generate(wordCount: bad)) { error in
                XCTAssertEqual(error as? PassphraseGeneratorError, .invalidWordCount)
            }
        }
    }

    func testOutputsDiffer() throws {
        let passphrases = try (0 ..< 20).map { _ in try PassphraseGenerator.generate() }
        XCTAssertEqual(Set(passphrases).count, 20)
    }

    func testEntropy() {
        // log2(7776 × 7775 × … × 7771): six distinct words.
        XCTAssertEqual(PassphraseGenerator.entropyBits(wordCount: 6), 77.546, accuracy: 0.001)
        XCTAssertEqual(PassphraseGenerator.entropyBits(wordCount: 10), 129.240, accuracy: 0.001)
    }

    /// Exhaustive: every 2-byte input either maps to an index or is redrawn, and each
    /// of the 7,776 indices is hit by exactly 8 inputs. So the choice has no bias.
    func testIndexMappingIsExactlyUniform() {
        XCTAssertEqual(PassphraseGenerator.acceptedLimit, 62_208)
        var hits = [Int](repeating: 0, count: 7_776)
        var redrawn = 0
        for value in 0 ..< 65_536 {
            if let index = PassphraseGenerator.index(fromRandomBytes: [UInt8(value >> 8), UInt8(value & 0xFF)]) {
                hits[index] += 1
            } else {
                redrawn += 1
            }
        }
        XCTAssertEqual(redrawn, 3_328)
        XCTAssertTrue(hits.allSatisfy { $0 == 8 })
        XCTAssertNil(PassphraseGenerator.index(fromRandomBytes: [1]))
    }
}
