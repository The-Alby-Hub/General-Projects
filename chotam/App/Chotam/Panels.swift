import AppKit
import EncryptionCore
import UniformTypeIdentifiers

/// Open and save panels. In the sandbox, a file the user picks here is the only kind
/// Chotam can read or write (`user-selected read-write`). Nothing is remembered:
/// no bookmarks, so a key file is chosen again each time (SECURITY.md D34, D35).
@MainActor
enum Panels {
    private static var identityType: UTType {
        UTType(filenameExtension: PublicIdentity.fileExtension) ?? .data
    }

    /// A `.pqid` file: a contact's identity, or your own when restoring.
    static func chooseIdentityFile() -> URL? {
        let panel = NSOpenPanel()
        panel.message = "Choose a Chotam identity (.pqid file)."
        panel.allowedContentTypes = [identityType]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Any file, used as a key file. Its contents are hashed into the identity.
    static func chooseKeyFile() -> URL? {
        let panel = NSOpenPanel()
        panel.message = "Choose your key file. It must be exactly the same file every time."
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.treatsFilePackagesAsDirectories = false
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Where to save your exported `.pqid`. The panel asks before replacing a file.
    static func exportLocation(suggestedName: String) -> URL? {
        let panel = NSSavePanel()
        panel.message = "Save your public identity. It contains no secret: share it with your contacts."
        panel.nameFieldStringValue = suggestedName
        panel.allowedContentTypes = [identityType]
        panel.canCreateDirectories = true
        return panel.runModal() == .OK ? panel.url : nil
    }
}
