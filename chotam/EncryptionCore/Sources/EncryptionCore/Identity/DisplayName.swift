/// Rules for identity and contact names.
///
/// A name inside a `.pqid` is chosen by whoever made it, so it's untrusted text: it
/// is only ever shown, never used as a path or to identify anyone. Keys are
/// identified by key IDs and fingerprints, never by name.
enum DisplayName {
    /// 1…64 bytes of UTF-8, not only whitespace, no control or bidi characters.
    static func isAcceptable(_ name: String) -> Bool {
        let byteCount = name.utf8.count
        guard byteCount > 0, byteCount <= IdentityFormat.maxNameBytes else { return false }
        guard name.contains(where: { !$0.isWhitespace }) else { return false }
        return !name.unicodeScalars.contains(where: TextRules.isForbiddenScalar)
    }
}
