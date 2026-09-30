import XCTest
@testable import EncryptionCore

/// The minimum password strength (SECURITY.md D6). Expected effective lengths were
/// worked out by hand and cross-checked with a line-by-line Python port of the rule.
final class PasswordPolicyTests: XCTestCase {
    private func assertAssessment(
        _ password: String,
        _ weakness: PasswordAssessment.Weakness?,
        effective: Int? = nil,
        passphrase: Bool = false,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let result = PasswordPolicy.assess(password)
        XCTAssertEqual(result.weakness, weakness, password.debugDescription, file: file, line: line)
        XCTAssertEqual(result.isAcceptable, weakness == nil, file: file, line: line)
        XCTAssertEqual(result.isPassphrase, passphrase, password.debugDescription, file: file, line: line)
        if let effective {
            XCTAssertEqual(result.effectiveLength, effective, password.debugDescription, file: file, line: line)
        }
    }

    func testFourteenCharacterBoundary() {
        assertAssessment("", .tooShort)
        assertAssessment("a", .tooShort)
        assertAssessment("k9#Lm2@pQ7!xR", .tooShort, effective: 13)
        assertAssessment("k9#Lm2@pQ7!xR4", nil, effective: 14)
    }

    func testRejectsRepeatsSequencesYearsAndCommonWords() {
        let predictable: [(String, Int)] = [
            ("aaaaaaaaaaaaaa", 1),  // the spec's own example
            (String(repeating: " ", count: 14), 1),
            ("abcdefghijklmnop", 1),
            ("zyxwvutsrqponmlk", 1),
            ("1234567890123456", 2),
            ("qwertyuiopasdfgh", 2),
            ("abcabcabcabcabcabc", 4),
            ("Password12345678", 2),
            ("P@ssw0rd!P@ssw0rd!", 3),
            ("l3tm31nl3tm31n!!", 4),
            ("iloveyouiloveyou", 2),
            ("summer2024summer2024", 3),
            ("Summer2024Holiday!", 10),
            ("PassWord1990xyzw", 4),
        ]
        for (password, effective) in predictable {
            assertAssessment(password, .tooPredictable, effective: effective)
        }
    }

    func testAcceptsOrdinaryStrongPasswords() {
        let strong: [(String, Int)] = [
            ("correct horse battery staple", 28),
            ("Blue-Tractor-47-Sings!", 22),
            ("tomato-dragon-FALCON-99", 18),
            ("born in 1987 at dawn", 17),
            ("mississippi river", 15),
            ("my cat likes cheese", 14),
            // Hebrew: "חותם סודי מאוד מאוד" (the repeated word counts once)
            ("\u{05D7}\u{05D5}\u{05EA}\u{05DD} \u{05E1}\u{05D5}\u{05D3}\u{05D9} \u{05DE}\u{05D0}\u{05D5}\u{05D3} \u{05DE}\u{05D0}\u{05D5}\u{05D3}", 15),
        ]
        for (password, effective) in strong {
            assertAssessment(password, nil, effective: effective)
        }
    }

    /// Length is counted in user-perceived characters after NFC, not bytes or scalars.
    func testCountsGraphemeClustersAfterNFC() {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}"  // one character, five scalars
        XCTAssertEqual(PasswordPolicy.assess("k9#Lm2@pQ7!xR" + family).characterCount, 14)
        assertAssessment("k9#Lm2@pQ7!xR" + family, nil, effective: 14)
        // "e" + combining acute is one character either way.
        XCTAssertEqual(PasswordPolicy.assess("k9#Lm2@pQ7!xRe\u{301}").characterCount, 14)
        XCTAssertEqual(PasswordPolicy.assess("k9#Lm2@pQ7!xRe\u{301}"), PasswordPolicy.assess("k9#Lm2@pQ7!xR\u{E9}"))
    }

    // MARK: Passphrase rule

    func testSixDistinctEFFWordsArePassphrases() {
        assertAssessment("abacus abdomen abdominal abide abiding ability", nil, effective: 46, passphrase: true)
        // Any case, any whitespace between words.
        assertAssessment("Abacus  ABDOMEN abdominal\tabide abiding ability", nil, passphrase: true)
        // Hyphenated EFF words are single words.
        assertAssessment("t-shirt yo-yo drop-down felt-tip abacus zoom", nil, passphrase: true)
    }

    func testOtherWordSequencesFallBackToTheCharacterRule() {
        // Five words: not a passphrase, but long enough as characters.
        assertAssessment("abacus abdomen abdominal abide abiding", nil, effective: 38)
        // A repeated word or a non-EFF word disqualifies the passphrase rule.
        assertAssessment("abacus abacus abdomen abdominal abide abiding", nil, effective: 39)
        XCTAssertFalse(PasswordPolicy.isEFFPassphrase("abacus abdomen abdominal abide abiding chotam"))
    }

    func testGeneratedPassphrasesAreAlwaysAccepted() throws {
        for _ in 0 ..< 200 {
            let passphrase = try PassphraseGenerator.generate()
            let result = PasswordPolicy.assess(passphrase)
            XCTAssertTrue(result.isAcceptable, passphrase)
            XCTAssertTrue(result.isPassphrase, passphrase)
        }
    }

    // MARK: Robustness

    func testHugeInputIsCheapAndRejectedIfRepetitive() {
        let start = Date()
        assertAssessment(String(repeating: "a", count: 100_000), .tooPredictable)
        assertAssessment(String(repeating: "ab", count: 50_000), .tooPredictable)
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }

    func testPatternHelpers() {
        let c = Array("xaaaab")
        XCTAssertEqual(PasswordPolicy.runLength(c, at: 1), 4)
        XCTAssertEqual(PasswordPolicy.runLength(Array("aab"), at: 0), 0, "a double is not a run")
        XCTAssertEqual(PasswordPolicy.sequenceLength(Array("xabcd"), at: 1), 4)
        XCTAssertEqual(PasswordPolicy.sequenceLength(Array("9876"), at: 0), 4)
        XCTAssertEqual(PasswordPolicy.sequenceLength(Array("asdf"), at: 0), 4)
        XCTAssertEqual(PasswordPolicy.sequenceLength(Array("lkj"), at: 0), 3)
        XCTAssertEqual(PasswordPolicy.sequenceLength(Array("ab"), at: 0), 0)
        XCTAssertEqual(PasswordPolicy.repeatedBlockLength(Array("xyzxyz"), at: 3), 3)
        XCTAssertEqual(PasswordPolicy.repeatedBlockLength(Array("xyxy"), at: 2), 2)
        XCTAssertEqual(PasswordPolicy.repeatedBlockLength(Array("xyzxy"), at: 3), 0)
        XCTAssertEqual(PasswordPolicy.yearLength(Array("x1999"), at: 1), 4)
        XCTAssertEqual(PasswordPolicy.yearLength(Array("1899"), at: 0), 0)
        XCTAssertEqual(PasswordPolicy.commonWordLength(Array("xpassword"), at: 1), 8)
    }
}
