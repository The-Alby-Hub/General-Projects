import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Where your identity lives on this Mac, and how it's unlocked (SECURITY.md D17, D18).
///
/// Your identity is **derived from a passphrase** Chotam generates: Argon2id, then HKDF
/// into the three key seeds (FORMAT.md §9.6). Nothing secret is stored anywhere:
///
/// | File in `folder` | Contents | Secret? |
/// |---|---|---|
/// | `identity.pqid` | your public identity: public keys, KDF parameters, name, self-signature | no |
/// | `contacts.chotam` | your contacts, encrypted with a key derived from your passphrase | no (encrypted) |
///
/// - The same passphrase (and key file, if any) always gives the same identity, so
///   contacts never re-verify you, and files sent while the app was closed still open.
/// - **There is no recovery.** A forgotten passphrase or a lost key file means the
///   identity, and every file sent to it, is gone.
/// - **Changing the passphrase means a new identity.** Contacts need the new `.pqid`.
/// - Chotam never uses the Keychain, for anything (SECURITY.md D18).
///
/// All calls are synchronous; unlocking takes a few seconds and about 1 GiB of memory,
/// so call them off the main thread.
public struct IdentityVault: Sendable {
    /// The folder holding the two files: the app's container in the app.
    public let folder: URL

    public init(folder: URL) {
        self.folder = folder
    }

    /// A new identity, and the passphrase that unlocks it.
    public struct Created: Sendable {
        public let identity: Identity
        /// Show it once, ask the user to write it down, then drop it. It can't be
        /// wiped (it's a `String`, SECURITY.md §7.3) and is never stored.
        public let passphrase: String
    }

    // MARK: Your identity

    /// The public identity stored on this Mac, or nil. Never needs the passphrase.
    public func storedIdentity() throws(IdentityError) -> PublicIdentity? {
        do {
            guard let bytes = try readFile(
                IdentityFormat.identityFileName, limit: IdentityFormat.pqidMaxFileSize, tooLarge: .identityTooLarge)
            else { return nil }
            return try PQIDCodec.decode(bytes)
        } catch {
            throw identityError(for: error, parsing: true)
        }
    }

    /// Creates a new identity and stores its public half on this Mac.
    ///
    /// - Parameters:
    ///   - keyFile: Optional. If given, the identity can only ever be unlocked with
    ///     this exact file as well as the passphrase, so a leaked passphrase alone is
    ///     useless. Losing the file loses the identity.
    /// - Returns: The unlocked identity and its passphrase (7 EFF words, about 90 bits).
    public func createIdentity(name: String, keyFile: URL? = nil) throws(IdentityError) -> Created {
        let passphrase = try IdentityPassphrase.generate()
        let identity = try createIdentity(
            name: name, passphrase: passphrase, keyFile: keyFile, cost: IdentityFormat.defaultKDFCost)
        return Created(identity: identity, passphrase: passphrase)
    }

    /// Unlocks the identity stored on this Mac.
    public func unlock(passphrase: String, keyFile: URL? = nil) throws(IdentityError) -> Identity {
        guard let stored = try storedIdentity() else { throw .noIdentity }
        return Identity(
            publicIdentity: stored, keys: try derive(stored, passphrase: passphrase, keyFile: keyFile), vault: self)
    }

    /// Sets up your existing identity on this Mac (a new or wiped Mac): `identity` is
    /// your own `.pqid`, e.g. from a contact or a copy you kept. It's only stored if
    /// the passphrase (and key file) derive exactly its keys.
    public func restore(
        _ identity: PublicIdentity, passphrase: String, keyFile: URL? = nil
    ) throws(IdentityError) -> Identity {
        guard try storedIdentity() == nil else { throw .identityExists }
        let keys = try derive(identity, passphrase: passphrase, keyFile: keyFile)
        try store(identity)
        return Identity(publicIdentity: identity, keys: keys, vault: self)
    }

    /// Removes your public identity and your contacts from this Mac.
    ///
    /// It can't delete the identity itself: anyone with your `.pqid` and passphrase
    /// can rebuild it. Lock any unlocked `Identity` too.
    public func forgetThisMac() throws(IdentityError) {
        do {
            // The identity file first: once it's gone, there's no identity here.
            try deleteFile(IdentityFormat.identityFileName)
            try deleteFile(IdentityFormat.contactsFileName)
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    // MARK: Internal (tests pass a cheap cost and a fixed passphrase)

    func createIdentity(
        name: String, passphrase: String, keyFile: URL?, cost: Argon2id.Cost
    ) throws(IdentityError) -> Identity {
        guard DisplayName.isAcceptable(name) else { throw .invalidName }
        guard try storedIdentity() == nil else { throw .identityExists }
        guard let secret = IdentityPassphrase.canonical(passphrase) else { throw .invalidPassphrase }
        let keyFileDigest = try keyFile.map { url throws(IdentityError) in try IdentityDerivation.keyFileDigest(url) }
        let kdf = IdentityKDF(
            cost: cost, salt: SecureRandom.bytes(IdentityFormat.kdfSaltSize), requiresKeyFile: keyFileDigest != nil)
        guard kdf.isAccepted else { throw .unexpected }

        do {
            let keys = try IdentityDerivation.derive(passphrase: secret, kdf: kdf, keyFileDigest: keyFileDigest)
            let body = try PQIDCodec.body(
                encryptionKey: [UInt8](keys.xwing.publicKey.rawRepresentation),
                mldsaKey: [UInt8](keys.mldsa.publicKey.rawRepresentation),
                ed25519Key: [UInt8](keys.ed25519.publicKey.rawRepresentation),
                kdf: kdf, name: name)
            let signature = try HybridSignature.sign(
                PQIDCodec.signedMessage(body: body), ed25519: keys.ed25519, mldsa: keys.mldsa)
            // Parse our own output with the import parser: we never store an identity
            // that a contact couldn't import.
            let publicIdentity = try PQIDCodec.decode(PQIDCodec.assemble(body: body, signature: signature))
            try store(publicIdentity)
            return Identity(publicIdentity: publicIdentity, keys: keys, vault: self)
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    /// Passphrase (+ key file) → keys, checked against `identity`'s public keys.
    func derive(_ identity: PublicIdentity, passphrase: String, keyFile: URL?) throws(IdentityError) -> DerivedKeys {
        // Cheap checks first: no Argon2id for a request that's going to be refused.
        switch (identity.kdf.requiresKeyFile, keyFile) {
        case (true, nil): throw .keyFileRequired
        case (false, .some): throw .keyFileNotUsed
        default: break
        }
        guard let secret = IdentityPassphrase.canonical(passphrase) else { throw .invalidPassphrase }
        let keyFileDigest = try keyFile.map { url throws(IdentityError) in try IdentityDerivation.keyFileDigest(url) }
        do {
            let keys = try IdentityDerivation.derive(passphrase: secret, kdf: identity.kdf, keyFileDigest: keyFileDigest)
            // The derived public keys must be exactly the stored ones. On a mismatch the
            // keys are dropped right here, never returned.
            guard keys.match(identity) else { throw CoreFailure(.wrongPassphrase) }
            return keys
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    /// Stores the public identity. A stale contacts file (from an identity forgotten
    /// half-way, say) belongs to no identity any more, so it goes first.
    private func store(_ identity: PublicIdentity) throws(IdentityError) {
        do {
            try deleteFile(IdentityFormat.contactsFileName)
            try writeFile(IdentityFormat.identityFileName, identity.encoded, replacing: false)
        } catch FileProblem.outputExists {
            throw .identityExists
        } catch {
            throw identityError(for: error, parsing: false)
        }
    }

    // MARK: Files

    /// The file's bytes, or nil if it doesn't exist. Files larger than `limit` are
    /// refused with `tooLarge`, without being read in full.
    func readFile(_ name: String, limit: Int, tooLarge: CoreFailure.Reason) throws -> [UInt8]? {
        let url = folder.appendingPathComponent(name, isDirectory: false)
        guard try FileStatus.lookup(url, followingLinks: false) != nil else { return nil }
        let source = try InputFile(opening: url)
        defer { source.close() }
        do {
            let data = try source.handle.read(upToCount: limit + 1) ?? Data()
            guard data.count <= limit else { throw CoreFailure(tooLarge) }
            return [UInt8](data)
        } catch let failure as CoreFailure {
            throw failure
        } catch {
            throw FileProblem.readFailed
        }
    }

    /// Writes the file atomically (owner-only, flushed, then renamed into place), so a
    /// crash leaves either the old file or the new one, never half of one.
    func writeFile(_ name: String, _ bytes: [UInt8], replacing: Bool) throws {
        try FileManager.default.createDirectory(
            at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let output = AtomicOutput(folder: folder)
        defer { output.discard() }
        try output.write(Data(bytes))
        _ = try output.commit(
            to: .file(folder.appendingPathComponent(name, isDirectory: false), replacingExisting: replacing))
    }

    private func deleteFile(_ name: String) throws {
        let url = folder.appendingPathComponent(name, isDirectory: false)
        guard try FileStatus.lookup(url, followingLinks: false) != nil else { return }
        do {
            try FileManager.default.removeItem(at: url)
        } catch {
            throw FileProblem.writeFailed
        }
    }
}
