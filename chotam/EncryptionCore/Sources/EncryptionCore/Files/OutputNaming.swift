import Foundation

/// Output names, and the rules for using the filename restored from inside an
/// encrypted file (SECURITY.md D12).
///
/// The restored name comes from the file's author, who may be hostile. It's only
/// used to name a new file inside a folder the user chose; it is never treated as a
/// path, and it never replaces anything.
enum OutputNaming {
    /// The usual limit on one path component (APFS, HFS+, ext4), in UTF-8 bytes.
    static let maxNameBytes = 255
    /// "Report.pdf", then "Report 2.pdf" … "Report 100.pdf", then `outputExists`.
    static let maxCandidates = 100
    /// Used when neither the restored name nor the encrypted file's name is usable.
    static let fallbackName = "Decrypted file"

    /// `Document.pdf` → `Document.pdf.enc`.
    static func encryptedName(for input: URL) -> String {
        input.lastPathComponent + ".enc"
    }

    /// `Document.pdf.enc` → `Document.pdf` (any case of `.enc`); anything else gets
    /// `.decrypted` appended.
    static func decryptedName(for input: URL) -> String {
        let name = input.lastPathComponent
        if name.count > 4, name.suffix(4).lowercased() == ".enc" {
            return String(name.dropLast(4))
        }
        return name + ".decrypted"
    }

    /// Whether a restored name may name a new file.
    ///
    /// On top of what the decoder already enforces (FORMAT.md §3: no `/`, no control
    /// or bidirectional characters, not `.` or `..`), it must not:
    /// - start with `.`: a hidden file such as `.zshrc` could be planted unseen;
    /// - contain `:`: Finder shows it as `/`, so the name would look like a path;
    /// - exceed 255 UTF-8 bytes: the file system would refuse it.
    static func isSafeToCreate(_ name: String) -> Bool {
        MetadataRecord.isAcceptable(name)
            && !name.hasPrefix(".")
            && !name.contains(":")
            && name.utf8.count <= maxNameBytes
    }

    /// Names to try, in order, for a decrypted file in a folder: the restored name if
    /// it's safe, otherwise the encrypted file's name without `.enc`.
    static func decryptionCandidates(storedFilename: String?, input: URL) -> [String] {
        let base = [storedFilename, decryptedName(for: input)]
            .compactMap { $0 }
            .first(where: isSafeToCreate) ?? fallbackName
        return candidates(for: base)
    }

    /// Names to try for an encrypted file in a folder: `Document.pdf.enc`, then
    /// `Document 2.pdf.enc`, so decrypting gives back a sensible `Document 2.pdf`.
    static func encryptionCandidates(for input: URL) -> [String] {
        candidates(for: input.lastPathComponent, appending: ".enc")
    }

    /// `Report.pdf` → `Report.pdf`, `Report 2.pdf`, `Report 3.pdf`, … Names that would
    /// be too long are skipped.
    static func candidates(for name: String, appending suffix: String = "") -> [String] {
        let (stem, fileExtension) = split(name)
        let numbered = (2 ... maxCandidates).map { "\(stem) \($0)\(fileExtension)\(suffix)" }
        return ([name + suffix] + numbered).filter { $0.utf8.count <= maxNameBytes }
    }

    /// Splits at the last `.`, unless it's the first character (`.profile` has no extension).
    private static func split(_ name: String) -> (stem: String, fileExtension: String) {
        guard let dot = name.lastIndex(of: "."), dot != name.startIndex else {
            return (name, "")
        }
        return (String(name[..<dot]), String(name[dot...]))
    }

    /// `folder/name`, checked to be exactly one new component inside `folder`.
    ///
    /// Belt and braces: names reaching here already passed `MetadataRecord.isAcceptable`,
    /// but the resulting URL is checked too, so no name can ever point outside the folder.
    static func url(for name: String, in folder: URL) throws -> URL {
        let url = folder.appendingPathComponent(name, isDirectory: false)
        guard MetadataRecord.isAcceptable(name),
              url.lastPathComponent == name,
              url.deletingLastPathComponent().standardizedFileURL.path
                == folder.standardizedFileURL.path
        else {
            throw FileProblem.invalidDestination
        }
        return url
    }
}
