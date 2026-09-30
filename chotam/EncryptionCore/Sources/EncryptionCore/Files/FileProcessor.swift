import Foundation

/// Where a result goes.
///
/// In the sandboxed app (`user-selected read-write` only), Chotam can write only
/// where the user pointed: a file chosen in a save panel, or a folder they granted.
/// It never assumes it may write beside the input (SECURITY.md D9).
public struct Destination: Sendable {
    enum Kind: Sendable {
        case file(URL, replacingExisting: Bool)
        case folder(URL)
    }

    let kind: Kind

    /// Exactly this file, e.g. from a save panel prefilled with
    /// `FileProcessor.encryptedName(for:)`.
    ///
    /// - Parameter replacingExisting: If a file is already there and this is false,
    ///   the operation fails with `outputExists` before any work is done. Pass true
    ///   only when the user confirmed replacing it (the save panel asks). It is then
    ///   replaced atomically, and only once the new file is complete.
    public static func file(_ url: URL, replacingExisting: Bool = false) -> Destination {
        Destination(kind: .file(url, replacingExisting: replacingExisting))
    }

    /// A new file in this folder, named by Chotam. It never replaces anything: if
    /// the name is taken it tries `Name 2.ext`, `Name 3.ext`, and so on.
    ///
    /// When decrypting, the file is named after the filename stored inside the
    /// encrypted file, if that name is safe (SECURITY.md D12).
    public static func folder(_ url: URL) -> Destination {
        Destination(kind: .folder(url))
    }
}

/// How to encrypt. Recipient mode (Phase 5) adds another factory here, e.g.
/// `.recipients(_:signedBy:)`; existing callers don't change.
public struct EncryptionMode: Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    enum Kind: Sendable {
        case password(String, cost: Argon2id.Cost)
    }

    let kind: Kind

    /// Password mode with Argon2id at libsodium's SENSITIVE preset (about 1 GiB).
    /// The password must pass `PasswordPolicy`.
    public static func password(_ password: String) -> EncryptionMode {
        EncryptionMode(kind: .password(password, cost: .sensitive))
    }

    /// Tests only: the cheapest cost v1 accepts, so they stay fast.
    static func password(_ password: String, cost: Argon2id.Cost) -> EncryptionMode {
        EncryptionMode(kind: .password(password, cost: cost))
    }

    // Never print the password, e.g. in a log or a debugger summary.
    public var description: String {
        switch kind {
        case .password: "EncryptionMode.password(<redacted>)"
        }
    }

    public var debugDescription: String { description }

    // No children, so `dump` and debuggers can't reach the password either.
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

/// How to decrypt. Recipient mode (Phase 5) adds another factory here, e.g.
/// `.identity(_:trusting:)`; existing callers don't change.
public struct DecryptionMode: Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    enum Kind: Sendable {
        case password(String)
    }

    let kind: Kind

    /// Password mode. The Argon2id cost comes from the file, within FORMAT.md §2.3's limits.
    public static func password(_ password: String) -> DecryptionMode {
        DecryptionMode(kind: .password(password))
    }

    public var description: String {
        switch kind {
        case .password: "DecryptionMode.password(<redacted>)"
        }
    }

    public var debugDescription: String { description }

    // No children, so `dump` and debuggers can't reach the password either.
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

/// The result of a successful decryption. Phase 5 adds who signed it.
public struct DecryptedFile: Equatable, Sendable {
    /// Where the plaintext was saved.
    public let url: URL
    /// The original filename stored inside the encrypted file, if any, for display.
    /// It comes from whoever made the file: show it as text only, never use it as
    /// a path. `Destination.folder` already uses it, safely, to name the output.
    public let storedFilename: String?
}

/// Encrypts and decrypts files on disk, safely (SECURITY.md D9).
///
/// - The result is written to a temp file and moved into place in one atomic step
///   only once it is complete. For a decryption, that's after every chunk has
///   authenticated. On any failure the temp file is deleted, and the destination
///   (including any file already there) is left exactly as it was.
/// - The input is only ever read. It is never modified, moved or deleted.
/// - Both calls are synchronous and slow on purpose (Argon2id takes about a second
///   and 1 GiB), so call them off the main thread.
public enum FileProcessor {
    /// Encrypts `input` and returns the URL of the new `.enc` file.
    ///
    /// The input's name is stored, encrypted, inside the file (FORMAT.md §3).
    public static func encrypt(
        _ input: URL, to destination: Destination, using mode: EncryptionMode
    ) throws(EncryptionError) -> URL {
        try encrypt(input, to: destination, using: mode, hooks: AtomicOutput.Hooks())
    }

    /// Decrypts `input`. Nothing is written under any output name unless the whole
    /// file authenticates.
    public static func decrypt(
        _ input: URL, to destination: Destination, using mode: DecryptionMode
    ) throws(DecryptionError) -> DecryptedFile {
        try decrypt(input, to: destination, using: mode, hooks: AtomicOutput.Hooks())
    }

    /// `Document.pdf` → `Document.pdf.enc`: the name to prefill in a save panel.
    public static func encryptedName(for input: URL) -> String {
        OutputNaming.encryptedName(for: input)
    }

    /// `Document.pdf.enc` → `Document.pdf`: the name to prefill in a save panel.
    /// It comes from the encrypted file's own name, which is known before decrypting.
    public static func decryptedName(for input: URL) -> String {
        OutputNaming.decryptedName(for: input)
    }

    // MARK: With test hooks

    static func encrypt(
        _ input: URL, to destination: Destination, using mode: EncryptionMode,
        hooks: AtomicOutput.Hooks
    ) throws(EncryptionError) -> URL {
        do {
            return try seal(input, to: destination, mode: mode, hooks: hooks)
        } catch {
            throw encryptionError(for: error)
        }
    }

    static func decrypt(
        _ input: URL, to destination: Destination, using mode: DecryptionMode,
        hooks: AtomicOutput.Hooks
    ) throws(DecryptionError) -> DecryptedFile {
        do {
            return try open(input, to: destination, mode: mode, hooks: hooks)
        } catch {
            throw decryptionError(for: error)
        }
    }

    // MARK: Implementation

    private static func seal(
        _ input: URL, to destination: Destination, mode: EncryptionMode, hooks: AtomicOutput.Hooks
    ) throws -> URL {
        let filename = input.lastPathComponent

        // Cheap checks first: nothing is opened, created or derived for a request
        // that's going to be refused anyway.
        switch mode.kind {
        case .password(let password, _):
            guard PasswordPolicy.assess(password).isAcceptable else {
                throw CoreFailure(.weakPassword)
            }
        }
        guard MetadataRecord.isAcceptable(filename) else {
            throw CoreFailure(.invalidFilename)
        }
        if case .folder = destination.kind,
           OutputNaming.encryptedName(for: input).utf8.count > OutputNaming.maxNameBytes {
            throw CoreFailure(.invalidFilename)
        }

        let source = try InputFile(opening: input)
        defer { source.close() }
        let plan = try prepare(destination, input: source.status)
        let output = AtomicOutput(folder: plan.folder, hooks: hooks)
        defer { output.discard() }

        switch mode.kind {
        case .password(let password, let cost):
            try PasswordMode.encrypt(
                password: password, filename: filename,
                from: FileHandleSource(source.handle), to: output, cost: cost)
        }
        return try output.commit(
            to: plan.target ?? .firstFree(in: plan.folder, names: OutputNaming.encryptionCandidates(for: input)))
    }

    private static func open(
        _ input: URL, to destination: Destination, mode: DecryptionMode, hooks: AtomicOutput.Hooks
    ) throws -> DecryptedFile {
        let source = try InputFile(opening: input)
        defer { source.close() }
        let plan = try prepare(destination, input: source.status)
        let output = AtomicOutput(folder: plan.folder, hooks: hooks)
        defer { output.discard() }

        let storedFilename: String?
        switch mode.kind {
        case .password(let password):
            storedFilename = try PasswordMode.open(
                password: password, from: FileHandleSource(source.handle), to: output)
        }

        // Every chunk has authenticated. Only now does the plaintext get a name. An
        // exact destination ignores the stored name; a folder uses it if it's safe.
        let target = plan.target ?? .firstFree(
            in: plan.folder,
            names: OutputNaming.decryptionCandidates(storedFilename: storedFilename, input: input))
        return DecryptedFile(url: try output.commit(to: target), storedFilename: storedFilename)
    }

    /// Checks the destination before any expensive work. The checks are repeated
    /// atomically at commit, so this is for early, clear errors, not for safety.
    ///
    /// Returns the folder that picks the temp file's volume, and the exact target
    /// (nil for a folder: the name is picked at commit).
    private static func prepare(
        _ destination: Destination, input: FileStatus
    ) throws -> (folder: URL, target: AtomicOutput.Target?) {
        switch destination.kind {
        case .file(let url, let replacingExisting):
            if let existing = try FileStatus.lookup(url, followingLinks: false) {
                // Never write over the input (or a hard link to it), a folder or a link.
                guard existing.kind == .regular, existing.identity != input.identity else {
                    throw FileProblem.invalidDestination
                }
                guard replacingExisting else { throw FileProblem.outputExists }
            }
            return (url.deletingLastPathComponent(), .file(url, replacingExisting: replacingExisting))

        case .folder(let folder):
            guard try FileStatus.lookup(folder, followingLinks: true)?.kind == .directory else {
                throw FileProblem.invalidDestination
            }
            return (folder, nil)
        }
    }

    // MARK: Errors

    static func encryptionError(for error: any Error) -> EncryptionError {
        if let problem = error as? FileProblem { return .file(problem) }
        let reason = (error as? CoreFailure)?.reason ?? .unexpected
        DebugLog.record(reason)
        switch reason {
        case .weakPassword: return .weakPassword
        case .invalidFilename: return .invalidFilename
        case .keyDerivationFailed: return .notEnoughMemory
        case .readFailed: return .file(.readFailed)
        case .writeFailed: return .file(.writeFailed)
        default: return .unexpected
        }
    }

    /// Anything that depends on the file's bytes or the password becomes the one
    /// generic `.failed`. Only failures that reveal nothing about either are
    /// reported as they are (SECURITY.md D13).
    static func decryptionError(for error: any Error) -> DecryptionError {
        if let problem = error as? FileProblem { return .file(problem) }
        let reason = (error as? CoreFailure)?.reason ?? .unexpected
        DebugLog.record(reason)
        switch reason {
        // Argon2id couldn't allocate what the header asks for. That's decided before
        // anything is authenticated, and the cost is public header data.
        case .keyDerivationFailed: return .notEnoughMemory
        // The OS failed to read the input or write the output.
        case .readFailed: return .file(.readFailed)
        case .writeFailed: return .file(.writeFailed)
        default: return .failed
        }
    }
}
