/// The encrypted metadata record at the start of the plaintext stream
/// (FORMAT.md §3): `nameLength (UInt16) ‖ name (UTF-8)`.
///
/// The original filename lives here rather than in the header, so it's
/// encrypted and authenticated instead of readable by anyone holding the file.
enum MetadataRecord {
    static func encode(filename: String?) throws -> [UInt8] {
        guard let filename else { return [0, 0] }
        guard isAcceptable(filename) else { throw CoreFailure(.invalidFilename) }
        let utf8 = Array(filename.utf8)
        var w = ByteWriter()
        w.appendInteger(UInt16(utf8.count))
        w.appendBytes(utf8)
        return w.bytes
    }

    /// Parses the record from the start of chunk 0's plaintext.
    /// Returns the filename and the offset where the file contents begin.
    static func decode(_ plaintext: [UInt8]) throws -> (filename: String?, contentOffset: Int) {
        var r = ByteReader(plaintext, failure: .malformedMetadata)
        let length = Int(try r.readUInt16())
        guard length > 0 else { return (nil, r.offset) }
        guard length <= FormatV1.maxFilenameBytes else {
            throw CoreFailure(.malformedMetadata)
        }
        let nameBytes = try r.readBytes(length)
        guard let name = TextRules.strictUTF8(nameBytes), isAcceptable(name) else {
            throw CoreFailure(.malformedMetadata)
        }
        return (name, r.offset)
    }

    /// A single path component that's safe to create and to show in the UI.
    static func isAcceptable(_ name: String) -> Bool {
        let byteCount = name.utf8.count
        guard byteCount > 0, byteCount <= FormatV1.maxFilenameBytes else { return false }
        guard name != ".", name != ".." else { return false }
        // "/" would make a path, not a name. Controls and bidi controls: TextRules.
        return !name.unicodeScalars.contains { $0 == "/" || TextRules.isForbiddenScalar($0) }
    }
}
