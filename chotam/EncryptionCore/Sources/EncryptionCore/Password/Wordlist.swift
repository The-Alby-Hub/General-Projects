import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The EFF large wordlist: 7,776 words, one per roll of five dice (CC-BY 3.0 US,
/// Electronic Frontier Foundation). Bundled byte-for-byte as EFF publishes it.
///
/// The file's SHA-256 is pinned. If the bundled file were ever swapped or edited, the
/// generator refuses to run rather than silently produce weaker passphrases.
enum Wordlist {
    static let resourceName = "eff_large_wordlist"
    static let wordCount = 7_776  // 6^5
    /// SHA-256 of https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
    static let expectedSHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"

    /// The words in dice order, or nil if the resource is missing or doesn't verify.
    static let words: [String]? = Wordlist.bundledData().flatMap { Wordlist.parse($0) }

    /// The raw bundled file, or nil if it is missing.
    static func bundledData() -> Data? {
        guard let url = Bundle.module.url(forResource: resourceName, withExtension: "txt") else {
            return nil
        }
        return try? Data(contentsOf: url)
    }

    static let lookup: Set<String>? = Wordlist.words.map { Set($0) }

    /// Verifies the pinned hash, then parses `ddddd<TAB>word<LF>` lines strictly:
    /// dice numbers 11111…66666 in order, words of `a`–`z` and `-`, no duplicates.
    static func parse(_ data: Data) -> [String]? {
        guard hexDigest(data) == expectedSHA256 else { return nil }

        let text = String(decoding: data, as: UTF8.self)
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        // The file ends with a newline, so the last piece is empty.
        guard lines.last == "" else { return nil }
        lines.removeLast()
        guard lines.count == wordCount else { return nil }

        var words: [String] = []
        words.reserveCapacity(wordCount)
        for (index, line) in lines.enumerated() {
            let fields = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard fields.count == 2,
                  String(fields[0]) == diceNumber(index),
                  !fields[1].isEmpty,
                  fields[1].allSatisfy({ ("a"..."z").contains($0) || $0 == "-" })
            else { return nil }
            words.append(String(fields[1]))
        }
        guard Set(words).count == wordCount else { return nil }
        return words
    }

    /// The five dice faces for `index`: 0 → "11111", 7775 → "66666".
    static func diceNumber(_ index: Int) -> String {
        var value = index
        var faces: [Character] = []
        for _ in 0 ..< 5 {
            faces.append(Character(String(value % 6 + 1)))
            value /= 6
        }
        return String(faces.reversed())
    }

    static func hexDigest(_ data: Data) -> String {
        SHA256.hash(data: data).map { byte in
            let hex = String(byte, radix: 16)
            return byte < 0x10 ? "0" + hex : hex
        }.joined()
    }
}
