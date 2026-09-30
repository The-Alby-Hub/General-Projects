import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Strict encoder and parser for `.pqid` v1, the public identity file (FORMAT.md §9).
///
/// ```
/// "CHOTAMID" ‖ version=1 (u16) ‖ 1216 (u16) ‖ X-Wing public key ‖ 1952 (u16) ‖ ML-DSA-65 public key
///            ‖ nameLength (u8, 0…64) ‖ name ‖ 3309 (u16) ‖ selfSignature
/// selfSignature = ML-DSA-65.sign("Chotam v1 identity signature" ‖ every byte before it)
/// ```
///
/// It only ever holds public keys. The parser is written for hostile input, like the
/// header parser: size cap first, then fixed fields, exact lengths, no trailing bytes,
/// and only then the cryptographic checks. It only ever throws `CoreFailure`.
enum PQIDCodec {
    // MARK: Encoding

    /// Everything the self-signature covers.
    static func body(encryptionKey: [UInt8], signingKey: [UInt8], name: String?) throws -> [UInt8] {
        guard encryptionKey.count == IdentityFormat.xwingPublicKeySize,
              signingKey.count == IdentityFormat.mldsa65PublicKeySize
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
        w.appendInteger(UInt16(signingKey.count))
        w.appendBytes(signingKey)
        w.appendInteger(UInt8(nameBytes.count))
        w.appendBytes(nameBytes)
        return w.bytes
    }

    /// The message the identity's ML-DSA-65 key signs. The label keeps it apart from
    /// a file signature (FORMAT.md §6.3), whose message starts with a different one.
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
        guard Int(try r.readUInt16()) == IdentityFormat.xwingPublicKeySize else {
            throw CoreFailure(.identityMalformed)
        }
        let encryptionKey = try r.readBytes(IdentityFormat.xwingPublicKeySize)
        guard Int(try r.readUInt16()) == IdentityFormat.mldsa65PublicKeySize else {
            throw CoreFailure(.identityMalformed)
        }
        let signingKey = try r.readBytes(IdentityFormat.mldsa65PublicKeySize)

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
        let bodyLength = r.offset

        guard Int(try r.readUInt16()) == IdentityFormat.mldsa65SignatureSize else {
            throw CoreFailure(.identityMalformed)
        }
        let signature = try r.readBytes(IdentityFormat.mldsa65SignatureSize)
        guard r.isAtEnd else {
            throw CoreFailure(.identityTrailingBytes)
        }

        // 4. The keys. FIPS 203 requires every ML-KEM coefficient to be below q; we
        //    check it ourselves too, so the rule holds on every platform and SDK.
        guard MLKEMEncoding.isCanonical(Array(encryptionKey.prefix(IdentityFormat.mlkem768EncodedVectorSize))) else {
            throw CoreFailure(.identityInvalidKey)
        }
        let xwing: XWingMLKEM768X25519.PublicKey
        let mldsa: MLDSA65.PublicKey
        do {
            xwing = try XWingMLKEM768X25519.PublicKey(rawRepresentation: encryptionKey)
            mldsa = try MLDSA65.PublicKey(rawRepresentation: signingKey)
        } catch {
            throw CoreFailure(.identityInvalidKey)
        }

        // 5. The self-signature: the holder of this ML-DSA key vouches for this
        //    X-Wing key and name (SECURITY.md D14). It does NOT say who that holder
        //    is; only comparing fingerprints does.
        let message = signedMessage(body: Array(bytes.prefix(bodyLength)))
        guard mldsa.isValidSignature(signature, for: message) else {
            throw CoreFailure(.identityBadSignature)
        }

        return PublicIdentity(
            encryptionKey: xwing, signingKey: mldsa,
            encryptionKeyBytes: encryptionKey, signingKeyBytes: signingKey,
            suggestedName: name, encoded: bytes)
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
