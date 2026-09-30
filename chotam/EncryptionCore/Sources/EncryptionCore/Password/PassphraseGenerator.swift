import Foundation

/// Why a passphrase couldn't be generated.
public enum PassphraseGeneratorError: Error, Equatable, Sendable {
    /// The word count is outside `PassphraseGenerator.wordCountRange`.
    case invalidWordCount
    /// The bundled wordlist is missing or doesn't match its pinned hash.
    case wordlistUnavailable
}

/// Builds passphrases from the EFF large wordlist using the system CSPRNG.
public enum PassphraseGenerator {
    /// Six words is the spec's minimum and about 77.5 bits.
    public static let defaultWordCount = 6
    public static let wordCountRange = 6...10
    /// A space, not a hyphen: four EFF words contain hyphens ("t-shirt", "yo-yo").
    public static let separator = " "

    /// Distinct, lowercase EFF words joined by single spaces. Always accepted by
    /// `PasswordPolicy.assess(_:)`.
    public static func generate(wordCount: Int = defaultWordCount) throws -> String {
        guard wordCountRange.contains(wordCount) else {
            throw PassphraseGeneratorError.invalidWordCount
        }
        guard let words = Wordlist.words else {
            throw PassphraseGeneratorError.wordlistUnavailable
        }
        var chosen: [String] = []
        while chosen.count < wordCount {
            let word = words[randomIndex()]
            // Words are distinct so the passphrase always passes the policy's
            // passphrase rule. This costs under 0.01 bits for six words.
            if !chosen.contains(word) {
                chosen.append(word)
            }
        }
        return chosen.joined(separator: separator)
    }

    /// Entropy of `generate(wordCount:)`: log2(7776 × 7775 × …) over distinct words.
    public static func entropyBits(wordCount: Int) -> Double {
        (0 ..< max(wordCount, 0)).reduce(0.0) { bits, k in
            bits + log2(Double(Wordlist.wordCount - k))
        }
    }

    // MARK: Uniform index

    /// 8 × 7776 = 62208 two-byte values map evenly onto the words; the other 3328
    /// (about 5%) are redrawn. A plain `value % 7776` would favour low indices.
    static let acceptedLimit = (65_536 / Wordlist.wordCount) * Wordlist.wordCount

    /// Maps two random bytes to an index, or nil if they must be redrawn.
    static func index(fromRandomBytes bytes: [UInt8]) -> Int? {
        guard bytes.count == 2 else { return nil }
        let value = Int(bytes[0]) << 8 | Int(bytes[1])
        guard value < acceptedLimit else { return nil }
        return value % Wordlist.wordCount
    }

    /// A uniformly random index in 0..<7776, by rejection sampling from the CSPRNG.
    private static func randomIndex() -> Int {
        while true {
            if let index = index(fromRandomBytes: SecureRandom.bytes(2)) {
                return index
            }
        }
    }
}
