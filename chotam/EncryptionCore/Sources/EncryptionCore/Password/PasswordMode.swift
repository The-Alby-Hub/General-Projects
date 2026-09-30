/// Password mode: Argon2id(password) → HKDF key schedule → streaming AES-256-GCM
/// (FORMAT.md §2.3, §4). Salts, nonces and keys are generated inside; callers only
/// pass a password and streams.
///
/// Internal: callers use `FileProcessor` with `EncryptionMode.password` /
/// `DecryptionMode.password`, which adds the safe temp-file handling.
enum PasswordMode {
    /// Encrypts `source` to `sink`.
    ///
    /// - Parameter cost: Always `.sensitive` in production. Tests pass the cheapest
    ///   accepted cost so they stay fast; the format stores whatever was used.
    /// - Throws: `CoreFailure(.weakPassword)` if `PasswordPolicy` rejects the
    ///   password. The check lives here, not only in the UI, so no caller can
    ///   create a weak-password file.
    static func encrypt(
        password: String,
        filename: String?,
        from source: any ByteSource,
        to sink: any ByteSink,
        cost: Argon2id.Cost = .sensitive
    ) throws {
        guard PasswordPolicy.assess(password).isAcceptable else {
            throw CoreFailure(.weakPassword)
        }
        // Check the name before spending a second and 1 GiB on Argon2id.
        if let filename, !MetadataRecord.isAcceptable(filename) {
            throw CoreFailure(.invalidFilename)
        }
        // Fresh 16-byte salt per file: the same password never gives the same IKM twice.
        let salt = SecureRandom.bytes(FormatV1.argon2SaltSize)
        let ikm = try Argon2id.deriveIKM(password: password, salt: salt, cost: cost)
        let parameters = FileHeader.ModeParameters.password(
            .init(argon2Salt: salt, opsLimit: cost.opsLimit, memLimit: cost.memLimit))
        _ = try StreamSealer.seal(
            ikm: ikm, parameters: parameters, filename: filename, from: source, to: sink)
    }

    /// Decrypts `source` to `sink` and returns the stored filename, if any.
    ///
    /// Every failure (wrong password, tampering, malformed input, not a password-mode
    /// file, or Argon2id running out of memory) is the single `DecryptionFailed`.
    /// Plaintext reaches `sink` chunk by chunk as each authenticates, so `sink` must
    /// be a temp file that is only kept if this returns (`AtomicOutput`).
    static func decrypt(
        password: String,
        from source: any ByteSource,
        to sink: any ByteSink
    ) throws(DecryptionFailed) -> String? {
        do {
            return try open(password: password, from: source, to: sink)
        } catch {
            throw publicDecryptionError(error)
        }
    }

    /// `decrypt`, but throwing the precise internal reason, for tests.
    ///
    /// - Parameter onDeriveKey: Test hook, called just before Argon2id runs.
    static func open(
        password: String,
        from source: any ByteSource,
        to sink: any ByteSink,
        onDeriveKey: (() -> Void)? = nil
    ) throws -> String? {
        // The parser checks the magic, version, sizes and the Argon2id ranges
        // (FORMAT.md §7) before anything expensive, so a crafted header can't
        // demand more than 1 GiB or ops 8.
        let (header, rawHeader) = try HeaderCodec.read(from: source)
        guard case .password(let parameters) = header.parameters else {
            throw CoreFailure(.wrongMode)
        }
        onDeriveKey?()
        let ikm = try Argon2id.deriveIKM(
            password: password,
            salt: parameters.argon2Salt,
            cost: .init(opsLimit: parameters.opsLimit, memLimit: parameters.memLimit))
        // A wrong password gives a different IKM, which fails the constant-time
        // commitment check before any chunk is opened.
        let summary = try StreamOpener.open(
            ikm: ikm, header: header, rawHeader: rawHeader, body: source,
            trailerLength: 0, to: sink)
        return summary.filename
    }
}
