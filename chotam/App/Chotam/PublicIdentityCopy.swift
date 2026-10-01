import AppKit
import EncryptionCore

/// The only clipboard use in Chotam: your **public** identity, as text to paste into a
/// message. Never a passphrase or a password (SECURITY.md D34).
@MainActor
enum PublicIdentityCopy {
    static func copy(_ identity: PublicIdentity) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(identity.exportedString, forType: .string)
    }
}
