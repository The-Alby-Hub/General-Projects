/// Fixed sizes and labels for identities (FORMAT.md §6.1, §9 and §10).
enum IdentityFormat {
    // Key sizes. X-Wing (draft-connolly-cfrg-xwing-kem): ML-KEM-768 encapsulation key
    // (1184) ‖ X25519 public key (32). ML-DSA-65: FIPS 204. Tests assert these
    // against the SDK.
    static let xwingPublicKeySize = 1216
    static let mlkem768EncodedVectorSize = 1152  // the part of the ML-KEM key that holds coefficients
    static let mldsa65PublicKeySize = 1952
    static let mldsa65SignatureSize = FormatV1.mldsa65SignatureSize

    // Domain labels. Each hash or signature input starts with its own label, so a
    // value computed for one purpose can never be mistaken for another.
    static let encryptionKeyIDLabel = Array("Chotam v1 encryption key id".utf8)
    static let signingKeyIDLabel = Array("Chotam v1 signing key id".utf8)
    static let fingerprintLabel = Array("Chotam v1 identity fingerprint".utf8)
    static let selfSignatureLabel = Array("Chotam v1 identity signature".utf8)

    // Fingerprint: 160 bits = 32 Crockford base32 characters, shown as 8 groups of 4.
    // Grover's algorithm makes a second preimage cost about 2^80 (SECURITY.md D5).
    static let fingerprintBytes = 20
    static let fingerprintGroupLength = 4

    // .pqid v1 (FORMAT.md §9)
    static let pqidMagic = Array("CHOTAMID".utf8)
    static let pqidVersion: UInt16 = 1
    static let maxNameBytes = 64
    /// magic, version, 3 length fields, both keys, name length, signature: everything but the name.
    static let pqidFixedSize =
        8 + 2 + 2 + xwingPublicKeySize + 2 + mldsa65PublicKeySize + 1 + 2 + mldsa65SignatureSize
    static let pqidMaxSize = pqidFixedSize + maxNameBytes
    /// Hard caps, checked before anything is decoded: a hostile input can't make
    /// the parser allocate or hash much.
    static let pqidMaxFileSize = 8 * 1024
    static let pqidMaxStringLength = 12 * 1024

    // Contact record v1 (FORMAT.md §10), stored in the Keychain.
    static let contactMagic = Array("CHOTAMCT".utf8)
    static let contactVersion: UInt16 = 1
    // Own identity's public record v1 (FORMAT.md §10).
    static let ownIdentityMagic = Array("CHOTAMME".utf8)
    static let ownIdentityVersion: UInt16 = 1
}
