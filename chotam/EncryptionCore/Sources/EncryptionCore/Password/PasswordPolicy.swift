import Foundation

/// The result of checking a password against `PasswordPolicy`.
public struct PasswordAssessment: Equatable, Sendable {
    public enum Weakness: Equatable, Sendable {
        /// Fewer than 14 characters, and not a passphrase of 6 or more EFF words.
        case tooShort
        /// 14 or more characters, but repeats, sequences, years or common words
        /// leave fewer than 14 that count.
        case tooPredictable
    }

    /// nil when the password is accepted.
    public let weakness: Weakness?
    /// Characters (grapheme clusters) after Unicode NFC normalisation.
    public let characterCount: Int
    /// Characters that count, with each repeat, sequence, year or common word
    /// counted as one. Useful for a strength meter.
    public let effectiveLength: Int
    /// True when accepted as a passphrase of distinct EFF words.
    public let isPassphrase: Bool

    public var isAcceptable: Bool { weakness == nil }
}

/// The minimum password strength for password mode (SECURITY.md D6).
///
/// A password is accepted if either:
/// - it is at least 6 distinct words from the EFF large wordlist, separated by
///   whitespace (any case), which is at least 77.5 bits when the words are random; or
/// - it has at least 14 characters **and** an effective length of at least 14,
///   where each of these counts as a single character:
///   - a run of 3 or more identical characters (`aaaa`),
///   - an ascending or descending run of 3 or more (`abcd`, `4321`) or a keyboard-row
///     run (`qwerty`, `asdf`),
///   - an immediate repeat of the preceding 2 or more characters (`abcabc`),
///   - a year from 1900 to 2099,
///   - a common word or password from a short built-in list, also after undoing
///     common substitutions (`p@ssw0rd`).
///
/// It is a floor against the obvious mistakes, not an entropy estimate: it can't
/// tell a pet's name from random letters. Encryption enforces it; decryption never does.
public enum PasswordPolicy {
    public static let minimumLength = 14
    public static let minimumPassphraseWords = 6
    /// Pattern analysis looks at this many characters at most, so a huge paste stays cheap.
    static let maximumAnalysedLength = 256

    public static func assess(_ password: String) -> PasswordAssessment {
        let normalized = password.precomposedStringWithCanonicalMapping
        let characterCount = normalized.count
        let effective = effectiveLength(of: normalized)

        if isEFFPassphrase(normalized) {
            return PasswordAssessment(
                weakness: nil, characterCount: characterCount,
                effectiveLength: effective, isPassphrase: true)
        }
        let weakness: PasswordAssessment.Weakness?
        if characterCount < minimumLength {
            weakness = .tooShort
        } else if effective < minimumLength {
            weakness = .tooPredictable
        } else {
            weakness = nil
        }
        return PasswordAssessment(
            weakness: weakness, characterCount: characterCount,
            effectiveLength: effective, isPassphrase: false)
    }

    // MARK: Passphrase rule

    static func isEFFPassphrase(_ normalized: String) -> Bool {
        guard let lookup = Wordlist.lookup else { return false }
        let words = normalized.lowercased().split(whereSeparator: \.isWhitespace).map(String.init)
        return words.count >= minimumPassphraseWords
            && Set(words).count == words.count
            && words.allSatisfy { lookup.contains($0) }
    }

    // MARK: Character rule

    /// Greedy left-to-right scan: at each position, the longest pattern starting
    /// there is consumed and counts as one character.
    static func effectiveLength(of normalized: String) -> Int {
        let characters = Array(normalized.lowercased().prefix(maximumAnalysedLength))
        let substituted = characters.map { substitutions[$0] ?? $0 }
        var units = 0
        var i = 0
        while i < characters.count {
            let span = max(
                1,
                commonWordLength(substituted, at: i),
                repeatedBlockLength(characters, at: i),
                runLength(characters, at: i),
                sequenceLength(characters, at: i),
                yearLength(characters, at: i))
            units += 1
            i += span
        }
        return units
    }

    /// `aaa…`: 3 or more of the same character.
    static func runLength(_ c: [Character], at i: Int) -> Int {
        var j = i + 1
        while j < c.count, c[j] == c[i] { j += 1 }
        return j - i >= 3 ? j - i : 0
    }

    /// `abc`, `cba`, `123`, `qwe`, `lkj`: 3 or more by code point or along a keyboard row.
    static func sequenceLength(_ c: [Character], at i: Int) -> Int {
        max(codePointRunLength(c, at: i), keyboardRunLength(c, at: i))
    }

    private static func codePointRunLength(_ c: [Character], at i: Int) -> Int {
        guard i + 1 < c.count, let a = scalarValue(c[i]), let b = scalarValue(c[i + 1]) else { return 0 }
        let step = Int(b) - Int(a)
        guard step == 1 || step == -1 else { return 0 }
        var j = i + 1
        var previous = b
        while j + 1 < c.count, let next = scalarValue(c[j + 1]), Int(next) - Int(previous) == step {
            previous = next
            j += 1
        }
        let length = j - i + 1
        return length >= 3 ? length : 0
    }

    private static func keyboardRunLength(_ c: [Character], at i: Int) -> Int {
        var best = 0
        for row in keyboardRows {
            for start in row.indices where row[start] == c[i] {
                var k = 0
                while i + k < c.count, start + k < row.count, row[start + k] == c[i + k] { k += 1 }
                best = max(best, k)
            }
        }
        return best >= 3 ? best : 0
    }

    /// `abcabc`, `pass1pass1`: the next 2 or more characters repeat the ones just before.
    static func repeatedBlockLength(_ c: [Character], at i: Int) -> Int {
        var length = min(i, c.count - i, 64)
        while length >= 2 {
            if c[(i - length) ..< i] == c[i ..< (i + length)] {
                return length
            }
            length -= 1
        }
        return 0
    }

    /// Four digits from 1900 to 2099.
    static func yearLength(_ c: [Character], at i: Int) -> Int {
        guard i + 4 <= c.count else { return 0 }
        let digits = c[i ..< i + 4]
        guard digits.allSatisfy({ $0.isASCII && $0.isNumber }),
              let year = Int(String(digits)), (1900...2099).contains(year)
        else { return 0 }
        return 4
    }

    /// The longest common word starting at `i`, matched after substitutions.
    static func commonWordLength(_ c: [Character], at i: Int) -> Int {
        var best = 0
        for word in commonWords where word.count > best && i + word.count <= c.count {
            if c[i ..< i + word.count].elementsEqual(word) {
                best = word.count
            }
        }
        return best
    }

    private static func scalarValue(_ character: Character) -> UInt32? {
        let scalars = character.unicodeScalars
        guard scalars.count == 1 else { return nil }
        return scalars.first?.value
    }

    // MARK: Data

    /// Rows of a US keyboard, forwards and backwards.
    static let keyboardRows: [[Character]] = {
        let rows: [String] = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"]
        let forwards: [[Character]] = rows.map { Array($0) }
        return forwards + forwards.map { Array($0.reversed()) }
    }()

    /// Common look-alike substitutions, undone before matching common words only.
    static let substitutions: [Character: Character] = [
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
        "@": "a", "$": "s", "!": "i", "+": "t", "|": "l",
    ]

    /// Frequent passwords and password words, written by hand from general knowledge
    /// (no third-party list). All lowercase letters, 4 or more characters.
    static let commonWords: [[Character]] = commonWordList.map { Array($0) }

    private static let commonWordList: [String] = [
        "password", "passwort", "passwd", "pass", "qwerty", "qwertz", "azerty", "letmein",
        "welcome", "admin", "administrator", "login", "root", "guest", "default", "changeme",
        "secret", "access", "master", "test", "user", "iloveyou", "love", "loveme", "lovely",
        "princess", "angel", "baby", "sunshine", "shadow", "monkey", "dragon", "tiger",
        "football", "baseball", "soccer", "hockey", "basketball", "superman", "batman",
        "starwars", "pokemon", "trustno", "whatever", "freedom", "hello", "hallo", "bonjour",
        "shalom", "charlie", "michael", "jordan", "jennifer", "jessica", "ashley", "daniel",
        "andrew", "joshua", "thomas", "robert", "george", "michelle", "nicole", "hunter",
        "ranger", "buster", "tigger", "pepper", "ginger", "cookie", "cheese", "flower",
        "summer", "winter", "spring", "autumn", "january", "february", "march", "april",
        "june", "july", "august", "september", "october", "november", "december", "monday",
        "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "computer",
        "internet", "google", "apple", "iphone", "samsung", "facebook", "mustang", "ferrari",
        "harley", "matrix", "killer", "ninja", "maverick", "liverpool", "chelsea", "arsenal",
        "barcelona", "yankees", "chotam", "encrypt", "secure", "private",
    ]
}
