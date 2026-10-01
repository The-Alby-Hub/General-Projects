import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Strict encoder and parser for `.pqid` v1, the public identity file (FORMAT.md §9).
///
/// ```
/// "CHOTAMID" ‖ version=1 (u16)
///   ‖ 1216 (u16) ‖ X-Wing public key ‖ 1952 (u16) ‖ ML-DSA-65 public key ‖ 32 (u16) ‖ Ed25519 public key
///   ‖ KDF block: algorithm=1 (u8) ‖ flags (u8) ‖ opsLimit (u64) ‖ memLimit (u64) ‖ parallelism=1 (u8) ‖ salt (16)
///   ‖ nameLength (u8, 0…64) ‖ name ‖ extensionsLength (u16, 0…1024) ‖ extensions
///   ‖ 3373 (u16) ‖ selfSignature
/// selfSignature = Ed25519 ‖ ML-DSA-65, both over "Chotam v1 identity signature" ‖ every byte before it
/// ```
///
/// It only ever holds public data: three public keys, the public parameters needed to
/// re-derive the identity from its passphrase, a name and a signature. The parser is
/// written for hostile input, like the header parser: size cap first, then fixed fields,
/// exact lengths, no trailing bytes, and only then the cryptographic checks. It only
/// ever throws `CoreFailure`.
enum PQIDCodec {
    /// One extension entry (FORMAT.md §9.1). v1 defines none.
    struct Extension: Equatable {
        let type: UInt16
        let value: [UInt8]

        var isCritical: Bool { type & IdentityFormat.criticalExtensionBit != 0 }
    }

    // MARK: Encoding

    /// Everything the self-signature covers.
    static func body(
        encryptionKey: [UInt8], mldsaKey: [UInt8], ed25519Key: [UInt8],
        kdf: IdentityKDF, name: String?, extensions: [Extension] = []
    ) throws -> [UInt8] {
        guard encryptionKey.count == IdentityFormat.xwingPublicKeySize,
              mldsaKey.count == IdentityFormat.mldsa65PublicKeySize,
              ed25519Key.count == IdentityFormat.ed25519PublicKeySize,
              kdf.isAccepted
        else { throw CoreFailure(.identityMalformed) }
        let nameBytes = Array((name ?? "").utf8)
        if let name {
            guard DisplayName.isAcceptable(name) else { throw CoreFailure(.identityInvalidName) }
        }
        var w = ByteWriter()
        w.appendBytes(IdentityFormat.pqidMagic)
        w.appendInteger(IdentityFormat.pqidVersion)
        w.appendInteger(UInt16(encryptionKey.count))
        w.appendBytes(encryptionKey)
        w.appendInteger(UInt16(mldsaKey.count))
        w.appendBytes(mldsaKey)
        w.appendInteger(UInt16(ed25519Key.count))
        w.appendBytes(ed25519Key)
        w.appendInteger(IdentityFormat.kdfArgon2id)
        w.appendInteger(kdf.requiresKeyFile ? IdentityFormat.kdfFlagKeyFile : 0)
        w.appendInteger(kdf.cost.opsLimit)
        w.appendInteger(kdf.cost.memLimit)
        w.appendInteger(IdentityFormat.kdfParallelism)
        w.appendBytes(kdf.salt)
        w.appendInteger(UInt8(nameBytes.count))
        w.appendBytes(nameBytes)
        let encodedExtensions = try encode(extensions)
        w.appendInteger(UInt16(encodedExtensions.count))
        w.appendBytes(encodedExtensions)
        return w.bytes
    }

    /// The message both signing keys sign. The label keeps it apart from a file
    /// signature (FORMAT.md §6.3), whose message starts with a different one.
    static func signedMessage(body: [UInt8]) -> [UInt8] {
        IdentityFormat.selfSignatureLabel + body
    }

    static func assemble(body: [UInt8], signature: [UInt8]) -> [UInt8] {
        var w = ByteWriter()
        w.appendBytes(body)
        w.appendInteger(UInt16(signature.count))
        w.appendBytes(signature)
        return w.bytes
    }

    /// Entries in strictly increasing type order, type 0 unused, so each set of
    /// extensions has exactly one encoding.
    static func encode(_ extensions: [Extension]) throws -> [UInt8] {
        var w = ByteWriter()
        var previous: UInt16 = 0
        for entry in extensions {
            guard entry.type > previous, entry.value.count <= Int(UInt16.max) else {
                throw CoreFailure(.identityMalformed)
            }
            previous = entry.type
            w.appendInteger(entry.type)
            w.appendInteger(UInt16(entry.value.count))
            w.appendBytes(entry.value)
        }
        guard w.bytes.count <= IdentityFormat.maxExtensionsBytes else { throw CoreFailure(.identityMalformed) }
        return w.bytes
    }

    // MARK: Parsing

    static func decode(_ bytes: [UInt8]) throws -> PublicIdentity {
        // 1. Size cap, before anything else.
        guard bytes.count <= IdentityFormat.pqidMaxFileSize else {
            throw CoreFailure(.identityTooLarge)
        }
        var r = ByteReader(bytes, failure: .identityMalformed)

        // 2. Magic and version. A newer version is reported as such, so the UI can
        //    say "made by a newer Chotam" rather than "damaged".
        guard try r.readBytes(IdentityFormat.pqidMagic.count) == IdentityFormat.pqidMagic else {
            throw CoreFailure(.identityBadMagic)
        }
        guard try r.readUInt16() == IdentityFormat.pqidVersion else {
            throw CoreFailure(.identityUnsupportedVersion)
        }

        // 3. Fixed fields with exact lengths. Redundant in v1, rejected if different.
        let encryptionKey = try readKey(&r, size: IdentityFormat.xwingPublicKeySize)
        let mldsaKey = try readKey(&r, size: IdentityFormat.mldsa65PublicKeySize)
        let ed25519Key = try readKey(&r, size: IdentityFormat.ed25519PublicKeySize)

        // 4. The KDF block: public parameters for re-deriving the identity. Bounded
        //    here, so a substituted .pqid can't make an unlock run for minutes or
        //    ask for 64 GiB.
        guard try r.readUInt8() == IdentityFormat.kdfArgon2id else {
            throw CoreFailure(.identityUnsupportedVersion)
        }
        let flags = try r.readUInt8()
        guard flags & ~IdentityFormat.kdfFlagKeyFile == 0 else {
            throw CoreFailure(.identityUnsupportedVersion)
        }
        let cost = Argon2id.Cost(opsLimit: try r.readUInt64(), memLimit: try r.readUInt64())
        guard try r.readUInt8() == IdentityFormat.kdfParallelism else {
            throw CoreFailure(.identityMalformed)
        }
        let kdf = IdentityKDF(
            cost: cost, salt: try r.readBytes(IdentityFormat.kdfSaltSize),
            requiresKeyFile: flags & IdentityFormat.kdfFlagKeyFile != 0)
        guard kdf.isAccepted else {
            throw CoreFailure(.identityMalformed)
        }

        // 5. The name.
        let nameLength = Int(try r.readUInt8())
        guard nameLength <= IdentityFormat.maxNameBytes else {
            throw CoreFailure(.identityInvalidName)
        }
        let nameBytes = try r.readBytes(nameLength)
        var name: String?
        if nameLength > 0 {
            guard let decoded = TextRules.strictUTF8(nameBytes), DisplayName.isAcceptable(decoded) else {
                throw CoreFailure(.identityInvalidName)
            }
            name = decoded
        }

        // 6. Extensions, reserved for later versions (e.g. a "live mode" that signs
        //    per-transfer keys). Unknown non-critical entries are kept and ignored;
        //    an unknown critical one means "made by a newer Chotam".
        let extensionsLength = Int(try r.readUInt16())
        guard extensionsLength <= IdentityFormat.maxExtensionsBytes else {
            throw CoreFailure(.identityMalformed)
        }
        let extensions = try decodeExtensions(try r.readBytes(extensionsLength))
        if extensions.contains(where: \.isCritical) {
            throw CoreFailure(.identityUnsupportedVersion)
        }
        let bodyLength = r.offset

        guard Int(try r.readUInt16()) == IdentityFormat.hybridSignatureSize else {
            throw CoreFailure(.identityMalformed)
        }
        let signature = try r.readBytes(IdentityFormat.hybridSignatureSize)
        guard r.isAtEnd else {
            throw CoreFailure(.identityTrailingBytes)
        }

        // 7. The keys. FIPS 203 requires every ML-KEM coefficient to be below q; we
        //    check it ourselves too, so the rule holds on every platform and SDK.
        guard MLKEMEncoding.isCanonical(Array(encryptionKey.prefix(IdentityFormat.mlkem768EncodedVectorSize))) else {
            throw CoreFailure(.identityInvalidKey)
        }
        let xwing: XWingMLKEM768X25519.PublicKey
        let mldsa: MLDSA65.PublicKey
        let ed25519: Curve25519.Signing.PublicKey
        do {
            xwing = try XWingMLKEM768X25519.PublicKey(rawRepresentation: encryptionKey)
            mldsa = try MLDSA65.PublicKey(rawRepresentation: mldsaKey)
            ed25519 = try Curve25519.Signing.PublicKey(rawRepresentation: ed25519Key)
        } catch {
            throw CoreFailure(.identityInvalidKey)
        }

        // 8. The hybrid self-signature: the holder of both signing keys vouches for
        //    the X-Wing key, the KDF parameters and the name (SECURITY.md D14). It
        //    does NOT say who that holder is; only comparing fingerprints does.
        let message = signedMessage(body: Array(bytes.prefix(bodyLength)))
        guard HybridSignature.isValid(signature, for: message, ed25519: ed25519, mldsa: mldsa) else {
            throw CoreFailure(.identityBadSignature)
        }

        return PublicIdentity(
            encryptionKey: xwing, mldsaKey: mldsa, ed25519Key: ed25519,
            encryptionKeyBytes: encryptionKey, mldsaKeyBytes: mldsaKey, ed25519KeyBytes: ed25519Key,
            kdf: kdf, suggestedName: name, encoded: bytes)
    }

    private static func readKey(_ r: inout ByteReader, size: Int) throws -> [UInt8] {
        guard Int(try r.readUInt16()) == size else {
            throw CoreFailure(.identityMalformed)
        }
        return try r.readBytes(size)
    }

    private static func decodeExtensions(_ bytes: [UInt8]) throws -> [Extension] {
        var r = ByteReader(bytes, failure: .identityMalformed)
        var result: [Extension] = []
        var previous: UInt16 = 0
        while !r.isAtEnd {
            let type = try r.readUInt16()
            guard type > previous else { throw CoreFailure(.identityMalformed) }
            previous = type
            let length = Int(try r.readUInt16())
            result.append(Extension(type: type, value: try r.readBytes(length)))
        }
        return result
    }

    /// The copyable form: standard Base64 (with padding) of the exact `.pqid` bytes.
    /// Spaces and line breaks are ignored, so a string wrapped by an email client
    /// still imports. Anything else outside the alphabet is rejected.
    static func decode(string: String) throws -> PublicIdentity {
        guard string.utf8.count <= IdentityFormat.pqidMaxStringLength else {
            throw CoreFailure(.identityTooLarge)
        }
        var compact = String.UnicodeScalarView()
        for scalar in string.unicodeScalars where !" \t\r\n".unicodeScalars.contains(scalar) {
            compact.append(scalar)
        }
        guard let bytes = StrictBase64.decode(String(compact)) else {
            throw CoreFailure(.identityBadEncoding)
        }
        return try decode(bytes)
    }
}

/// Strict, platform-independent Base64 (RFC 4648 §4) decoding: the standard alphabet,
/// correct padding, and a canonical encoding (the unused bits of the last symbol are
/// zero), so each identity has exactly one string form.
enum StrictBase64 {
    static func decode(_ text: String) -> [UInt8]? {
        let symbols = Array(text.utf8)
        guard !symbols.isEmpty, symbols.count % 4 == 0 else { return nil }
        let padding = symbols.reversed().prefix(while: { $0 == UInt8(ascii: "=") }).count
        guard padding <= 2 else { return nil }
        for symbol in symbols.dropLast(padding) {
            guard value(of: symbol) != nil else { return nil }
        }
        guard let data = Data(base64Encoded: text) else { return nil }
        // Re-encoding must give back exactly the input: rejects non-zero spare bits.
        guard data.base64EncodedString() == text else { return nil }
        return [UInt8](data)
    }

    private static func value(of symbol: UInt8) -> UInt8? {
        switch symbol {
        case UInt8(ascii: "A") ... UInt8(ascii: "Z"): return symbol - UInt8(ascii: "A")
        case UInt8(ascii: "a") ... UInt8(ascii: "z"): return symbol - UInt8(ascii: "a") + 26
        case UInt8(ascii: "0") ... UInt8(ascii: "9"): return symbol - UInt8(ascii: "0") + 52
        case UInt8(ascii: "+"): return 62
        case UInt8(ascii: "/"): return 63
        default: return nil
        }
    }
}

/// FIPS 203 §7.2 "modulus check" for the coefficient part of an ML-KEM encapsulation key.
enum MLKEMEncoding {
    static let q: UInt16 = 3329

    /// Each 3 bytes hold two 12-bit little-endian coefficients; all must be < q.
    static func isCanonical(_ encoded: [UInt8]) -> Bool {
        guard encoded.count % 3 == 0 else { return false }
        var index = 0
        while index < encoded.count {
            let b0 = UInt16(encoded[index])
            let b1 = UInt16(encoded[index + 1])
            let b2 = UInt16(encoded[index + 2])
            let first = b0 | ((b1 & 0x0F) << 8)
            let second = (b1 >> 4) | (b2 << 4)
            guard first < q, second < q else { return false }
            index += 3
        }
        return true
    }
}
