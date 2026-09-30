/// Rules for text that comes from someone else (a stored filename, an identity's
/// name) and ends up on screen.
enum TextRules {
    /// C0 and C1 controls (NUL, newlines, escape sequences) and Unicode bidirectional
    /// controls. Bidi controls can make "invoice<RLO>fdp.exe" display as "invoiceexe.pdf".
    static func isForbiddenScalar(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x00 ... 0x1F, 0x7F ... 0x9F:
            true
        case 0x061C, 0x200E, 0x200F, 0x202A ... 0x202E, 0x2066 ... 0x2069:
            true
        default:
            false
        }
    }

    /// Strict UTF-8: decoding with replacement and re-encoding must round-trip,
    /// so invalid or overlong sequences are rejected rather than repaired.
    static func strictUTF8(_ bytes: [UInt8]) -> String? {
        let string = String(decoding: bytes, as: UTF8.self)
        return Array(string.utf8) == bytes ? string : nil
    }
}
