import Foundation

/// The generated identity passphrase, shown once to be written down (SECURITY.md D34).
///
/// It's a `String` because it has to be shown, and Strings can't be wiped (§7.3). The
/// view model holds it only until the user confirms they wrote it down, then drops it.
/// There is no copy action, on purpose.
public struct PassphraseReveal: Sendable, Equatable {
    public struct Word: Sendable, Equatable, Identifiable {
        /// 1-based, as written down.
        public let number: Int
        public let text: String
        public var id: Int { number }
    }

    public let words: [Word]

    public init(_ passphrase: String) {
        words = passphrase.split(whereSeparator: \.isWhitespace).enumerated().map {
            Word(number: $0.offset + 1, text: String($0.element))
        }
    }

    /// "I've written down all 7 words"
    public var confirmationText: String {
        "I've written down all \(words.count) words, in order."
    }
}

/// A fingerprint's 8 groups, numbered for reading aloud, and the comparison with one
/// typed in (SECURITY.md D5).
public struct FingerprintDisplay: Sendable, Equatable {
    public struct Group: Sendable, Equatable, Identifiable {
        public let number: Int
        public let text: String
        public var id: Int { number }
    }

    public let groups: [Group]

    public init(groups: [String]) {
        self.groups = groups.enumerated().map { Group(number: $0.offset + 1, text: $0.element) }
    }

    /// "1 80XX · 2 XYHV · …", for an accessibility label or a single line.
    public var spokenText: String {
        groups.map { "\($0.number) \($0.text)" }.joined(separator: ", ")
    }
}

/// What the user typed while comparing fingerprints.
public enum FingerprintMatch: Sendable, Equatable {
    /// Nothing typed: compare by reading aloud instead.
    case notTyped
    case matches
    case doesNotMatch

    public init(typed: String, matches: (String) -> Bool) {
        if typed.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            self = .notTyped
        } else {
            self = matches(typed) ? .matches : .doesNotMatch
        }
    }
}
