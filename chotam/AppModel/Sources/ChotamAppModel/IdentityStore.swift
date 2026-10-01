import EncryptionCore
import Foundation

/// Where the identity lives: `IdentityVault` in the app, a cheaper one in tests.
///
/// Every call is synchronous and may take seconds (Argon2id); the view models call it
/// through `Background`.
public protocol IdentityStore: Sendable {
    func storedIdentity() throws(IdentityError) -> PublicIdentity?
    /// A new identity and its generated passphrase, shown once and then dropped.
    func create(name: String, keyFile: URL?) throws(IdentityError) -> NewIdentity
    func unlock(passphrase: String, keyFile: URL?) throws(IdentityError) -> Identity
    func restore(_ identity: PublicIdentity, passphrase: String, keyFile: URL?) throws(IdentityError) -> Identity
    func forgetThisMac() throws(IdentityError)
}

/// A just-created identity, unlocked, and the passphrase to show once.
public struct NewIdentity: Sendable {
    public let identity: Identity
    public let passphrase: String

    public init(identity: Identity, passphrase: String) {
        self.identity = identity
        self.passphrase = passphrase
    }
}

extension IdentityVault: IdentityStore {
    public func create(name: String, keyFile: URL?) throws(IdentityError) -> NewIdentity {
        let created = try createIdentity(name: name, keyFile: keyFile)
        return NewIdentity(identity: created.identity, passphrase: created.passphrase)
    }
}

/// Turns a `.pqid` file's bytes, or a pasted Base64 string, into a public identity.
public enum IdentityImport {
    public static func parse(data: Data) throws(IdentityError) -> PublicIdentity {
        try PublicIdentity(importing: data)
    }

    /// Whitespace around the string (from a message or an email) is ignored.
    public static func parse(string: String) throws -> PublicIdentity {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw AppProblem.nothingToImport }
        return try PublicIdentity(importingString: trimmed)
    }
}

/// The folder the app keeps `identity.pqid` and `contacts.chotam` in: Application
/// Support inside the sandbox container (SECURITY.md §8).
public enum AppLocations {
    /// `~/Library/Containers/<bundle id>/Data/Library/Application Support/Chotam/` in
    /// the sandboxed app. The vault creates it when it first writes.
    public static var identityFolder: URL {
        URL.applicationSupportDirectory.appendingPathComponent("Chotam", isDirectory: true)
    }
}

/// Reads a `.pqid` file chosen by the user, refusing anything far larger than an
/// identity (at most 7,717 bytes) without reading it all.
public enum IdentityFile {
    static let readLimit = 16 * 1024

    public static func read(_ url: URL) throws(AppProblem) -> Data {
        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let data = try handle.read(upToCount: readLimit + 1) ?? Data()
            guard data.count <= readLimit else { throw AppProblem.identityFileUnreadable }
            return data
        } catch {
            throw .identityFileUnreadable
        }
    }

    /// Saves `identity`'s `.pqid` where the user chose in a save panel (which already
    /// asked before replacing a file). Public data only.
    public static func export(_ identity: PublicIdentity, to url: URL) throws(AppProblem) {
        do {
            try identity.exportedData.write(to: url)
        } catch {
            throw .exportFailed
        }
    }

    /// The suggested file name for exporting `identity`: its name, or "Identity".
    public static func exportName(for identity: PublicIdentity) -> String {
        let base = (identity.suggestedName ?? "")
            .components(separatedBy: CharacterSet(charactersIn: "/:\\").union(.controlCharacters))
            .joined(separator: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let safe = base.isEmpty || base.hasPrefix(".") ? "Identity" : base
        return safe + "." + PublicIdentity.fileExtension
    }
}
