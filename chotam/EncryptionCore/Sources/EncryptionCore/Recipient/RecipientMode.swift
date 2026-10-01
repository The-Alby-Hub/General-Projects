import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Who signed a recipient-mode file. Show it after every decryption: "Signed by: you",
/// "Signed by: Bob ✓ verified", or "Signed by: Bob (not verified)".
///
/// Only you and your contacts can sign a file Chotam opens. A file from anyone else is
/// refused with `DecryptionError.unknownSender` (SECURITY.md D20).
public enum Signer: Equatable, Sendable {
    /// Your own identity: a file you sent (you are always one of its recipients).
    case you
    /// A contact whose fingerprint you compared and marked as verified.
    case verifiedContact(Contact)
    /// A contact you imported but haven't verified: anyone could have handed you their
    /// identity. Say so clearly, and offer to compare fingerprints. The `Contact` can be
    /// passed straight to `Identity.markVerified(_:)`.
    case unverifiedContact(Contact)

    /// True for you and for verified contacts.
    public var isVerified: Bool {
        switch self {
        case .you, .verifiedContact: true
        case .unverifiedContact: false
        }
    }
}

/// Recipient mode: a random Data Key per file, wrapped to each recipient with HPKE
/// (X-Wing), and a hybrid Ed25519 + ML-DSA-65 signature over the header and every
/// ciphertext chunk (FORMAT.md §6).
///
/// Internal: callers use `FileProcessor` with `EncryptionMode.recipients` /
/// `DecryptionMode.identity`, which add the safe temp-file handling.
enum RecipientMode {
    /// HPKE base mode, X-Wing (KEM 0x647A), HKDF-SHA256, AES-256-GCM (FORMAT.md §6.2).
    /// X-Wing has no authenticated mode; the signature authenticates the sender.
    static let ciphersuite = HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256
    static let wrapContextLabel = Array("Chotam v1 wrap context".utf8)
    /// Differs from the `.pqid` label ("Chotam v1 identity signature") from its 11th
    /// byte, so a file signature can never stand in for a self-signature or back.
    static let signatureLabel = Array("Chotam v1 signature".utf8)
    /// Ed25519 (64) ‖ ML-DSA-65 (3309).
    static let trailerSize = IdentityFormat.hybridSignatureSize

    // MARK: Encrypting

    /// Recipients that were checked against the signing identity's current contacts.
    /// Only `check(_:signedBy:)` makes one, so `encrypt` can't skip the check.
    struct CheckedRecipients {
        let contacts: [PublicIdentity]
        let sender: Identity

        fileprivate init(contacts: [PublicIdentity], sender: Identity) {
            self.contacts = contacts
            self.sender = sender
        }
    }

    /// Checks, before any work, that the sender is unlocked and that every recipient is
    /// still one of the sender's contacts. A `RecipientList` isn't tied to an identity:
    /// it could hold a contact removed since it was made, or another identity's contacts.
    ///
    /// - Throws: `IdentityError` (`.locked`, `.contactsDamaged`, `.storageFailed`), or
    ///   `CoreFailure(.recipientsChanged)`.
    static func check(_ list: RecipientList, signedBy sender: Identity) throws -> CheckedRecipients {
        guard !sender.isLocked else { throw IdentityError.locked }
        let current = try sender.contacts()
        for contact in list.contacts {
            // Matched by keys (both key IDs), never by name. A contact never shares a
            // key with you (the contacts file enforces it), so this also keeps your own
            // key out of the contacts' stanzas.
            guard !contact.publicIdentity.sharesKey(with: sender.publicIdentity),
                  current.contains(where: { $0.publicIdentity == contact.publicIdentity })
            else { throw CoreFailure(.recipientsChanged) }
        }
        return CheckedRecipients(contacts: list.contacts.map(\.publicIdentity), sender: sender)
    }

    /// Encrypts `source` to the checked recipients plus the sender, signed by the sender.
    ///
    /// The private signing keys are taken from the identity only at the end, to sign.
    /// If it was locked in the meantime this throws `IdentityError.locked`, and the
    /// caller deletes the unfinished output.
    static func encrypt(
        to recipients: CheckedRecipients, filename: String?,
        from source: any ByteSource, to sink: any ByteSink
    ) throws {
        let sender = recipients.sender
        try seal(
            contacts: recipients.contacts, sender: sender.publicIdentity,
            sign: { message in
                try sender.withKeys { keys in
                    try HybridSignature.sign(message, ed25519: keys.ed25519, mldsa: keys.mldsa)
                }
            },
            filename: filename, from: source, to: sink)
    }

    /// Test knobs. Production code always uses the defaults.
    struct SealOptions {
        /// Write this commitment instead of the real one, and wrap and sign over it, so a
        /// test can build a validly signed file whose commitment doesn't match its key.
        var commitment: [UInt8]? = nil
    }

    /// The whole of FORMAT.md §6 for one file. `sign` receives the signed message
    /// (§6.3) and returns the 3373-byte hybrid signature.
    static func seal(
        contacts: [PublicIdentity], sender: PublicIdentity,
        sign: ([UInt8]) throws -> [UInt8],
        filename: String?, from source: any ByteSource, to sink: any ByteSink,
        options: SealOptions = SealOptions()
    ) throws {
        // Contacts' stanzas sorted by key ID, so the header says nothing about the order
        // they were chosen in; the sender's own stanza last (encrypt to self, D21).
        let sorted = contacts.sorted { $0.encryptionKeyID.bytes.lexicographicallyPrecedes($1.encryptionKeyID.bytes) }
        let ordered = sorted + [sender]
        guard ordered.count <= FormatV1.maxRecipients else { throw CoreFailure(.recipientCountOutOfRange) }

        // A fresh random 256-bit Data Key per file (CryptoKit's CSPRNG). It is the IKM of
        // the key schedule (FORMAT.md §4), so the file key and commitment derive from it.
        // It lives only in this SymmetricKey, which CryptoKit zeroes when released.
        let dataKey = SymmetricKey(size: .bits256)

        // Placeholder stanzas with the final key IDs: the header layout and everything
        // the wrap context covers are fixed before any key is wrapped.
        let placeholders = ordered.map {
            FileHeader.RecipientStanza(
                keyID: $0.encryptionKeyID.bytes,
                encapsulatedKey: [UInt8](repeating: 0, count: FormatV1.xwingEncapsulatedKeySize),
                wrappedDataKey: [UInt8](repeating: 0, count: FormatV1.wrappedDataKeySize))
        }
        let draft = FileHeader.ModeParameters.recipients(
            .init(senderKeyID: sender.signingKeyID.bytes, stanzas: placeholders))
        let commitmentOverride = options.commitment

        let summary = try StreamSealer.seal(
            ikm: dataKey, parameters: draft, filename: filename, from: source, to: sink,
            prepareHeader: { header in
                if let commitmentOverride {
                    header.commitment = commitmentOverride
                }
                // The wrap context covers the prelude, the common fields (commitment
                // included), the sender and every key ID: everything but the wrapped
                // keys themselves (FORMAT.md §6.2).
                let context = try RecipientMode.wrapContext(rawHeader: try HeaderCodec.encode(header))
                let stanzas = try ordered.map { recipient in
                    try RecipientMode.wrap(
                        dataKey, to: recipient.encryptionKey, keyID: recipient.encryptionKeyID.bytes, context: context)
                }
                header.parameters = .recipients(.init(senderKeyID: sender.signingKeyID.bytes, stanzas: stanzas))
            })

        let trailer = try sign(signedMessage(
            headerHash: summary.headerHash, ciphertextDigest: summary.ciphertextDigest, chunkCount: summary.chunkCount))
        guard trailer.count == trailerSize else { throw CoreFailure(.unexpected) }
        try sink.write(Data(trailer))
    }

    /// One HPKE single-shot seal (sequence number 0) of the Data Key to one recipient:
    /// `info` = wrap context, `aad` = their key ID (FORMAT.md §6.2). The Data Key goes
    /// from CryptoKit's storage straight into HPKE, without a copy.
    static func wrap(
        _ dataKey: SymmetricKey, to key: XWingMLKEM768X25519.PublicKey, keyID: [UInt8], context: [UInt8]
    ) throws -> FileHeader.RecipientStanza {
        do {
            var hpke = try HPKE.Sender(recipientKey: key, ciphersuite: ciphersuite, info: Data(context))
            let wrapped = try dataKey.withUnsafeBytes { bytes in
                try hpke.seal(bytes, authenticating: keyID)
            }
            let stanza = FileHeader.RecipientStanza(
                keyID: keyID, encapsulatedKey: [UInt8](hpke.encapsulatedKey), wrappedDataKey: [UInt8](wrapped))
            guard stanza.encapsulatedKey.count == FormatV1.xwingEncapsulatedKeySize,
                  stanza.wrappedDataKey.count == FormatV1.wrappedDataKeySize
            else { throw CoreFailure(.unexpected) }
            return stanza
        } catch {
            throw CoreFailure(.unexpected)
        }
    }

    // MARK: Decrypting

    struct Opened {
        let filename: String?
        let signer: Signer
    }

    /// Decrypts `source` with `identity`, in two passes (SECURITY.md D19), and returns
    /// the stored filename and who signed the file.
    ///
    /// Order (FORMAT.md §7), each step only if the previous one passed:
    /// 1. the identity is unlocked (else `IdentityError.locked`, before reading anything);
    /// 2. the strict header parser;
    /// 3. your stanza, by key ID (none: not for you, the generic failure);
    /// 4. the signer: you, or a contact (else `.unknownSender`);
    /// 5. pass 1: the whole body is read and the hybrid signature verified over the
    ///    header hash, the ciphertext hash and the chunk count, with no secret;
    /// 6. HPKE unwraps the Data Key;
    /// 7. pass 2: the header is read again and must be identical; the commitment is
    ///    checked before any chunk is opened; every chunk is decrypted into `sink`, and
    ///    the ciphertext hash, chunk count and trailer must equal pass 1's.
    ///
    /// Nothing reaches `sink` before step 7, so a forged file never writes plaintext.
    /// `sink` must still be a temp file that is only kept if this returns: a file
    /// changed between the passes fails during step 7 (D19).
    ///
    /// - Parameters:
    ///   - beforeSecondPass: Called just before pass 2; `FileProcessor` re-checks the
    ///     input's size there, to stop early if it changed.
    ///   - onChunkOpen: Test hook, called before each AES-GCM open attempt.
    static func open(
        with identity: Identity, from source: any RewindableSource, to sink: any ByteSink,
        beforeSecondPass: () throws -> Void = {}, onChunkOpen: (() -> Void)? = nil
    ) throws -> Opened {
        guard !identity.isLocked else { throw IdentityError.locked }
        let me = identity.publicIdentity

        let (header, rawHeader) = try HeaderCodec.read(from: source)
        guard case .recipients(let parameters) = header.parameters else {
            throw CoreFailure(.wrongMode)
        }

        // Not for you wins over an unknown sender (decided 2026-10-01): a file you can't
        // open anyway shouldn't suggest importing whoever made it.
        guard let stanza = parameters.stanzas.first(where: { $0.keyID == me.encryptionKeyID.bytes }) else {
            throw CoreFailure(.notARecipient)
        }
        let (signer, signingKey) = try findSigner(KeyID(bytes: parameters.senderKeyID), for: identity)

        // Pass 1: no secret is used and nothing is written.
        let headerHash = Array(SHA256.hash(data: rawHeader))
        let firstPass = try digestBody(from: source)
        let message = signedMessage(
            headerHash: headerHash, ciphertextDigest: firstPass.ciphertextDigest, chunkCount: firstPass.chunkCount)
        guard HybridSignature.isValid(
            firstPass.trailer, for: message, ed25519: signingKey.ed25519Key, mldsa: signingKey.mldsaKey)
        else { throw CoreFailure(.badSignature) }

        // Only a correctly signed file gets this far. Now the private key is used.
        let context = try wrapContext(rawHeader: rawHeader)
        let dataKey = try identity.withKeys { keys in
            try unwrap(stanza, context: context, with: keys.xwing)
        }

        // Pass 2.
        try beforeSecondPass()
        try source.rewind()
        let (_, rawAgain) = try HeaderCodec.read(from: source)
        guard rawAgain == rawHeader else { throw CoreFailure(.changedBetweenPasses) }
        // StreamOpener checks the commitment (constant time) before opening any chunk,
        // so a Data Key that isn't the one this header commits to opens nothing.
        let secondPass = try StreamOpener.open(
            ikm: dataKey, header: header, rawHeader: rawHeader, body: source,
            trailerLength: trailerSize, to: sink, onChunkOpen: onChunkOpen)
        guard secondPass.ciphertextDigest == firstPass.ciphertextDigest,
              secondPass.chunkCount == firstPass.chunkCount,
              secondPass.trailer == firstPass.trailer
        else { throw CoreFailure(.changedBetweenPasses) }

        return Opened(filename: secondPass.filename, signer: signer)
    }

    /// You, or the contact with this signing key ID. Contacts are read from the unlocked
    /// identity's encrypted contacts file, now, so a removed contact is never accepted.
    static func findSigner(_ id: KeyID, for identity: Identity) throws -> (Signer, PublicIdentity) {
        if id == identity.publicIdentity.signingKeyID {
            return (.you, identity.publicIdentity)
        }
        guard let contact = try identity.contact(signingKeyID: id) else {
            throw CoreFailure(.unknownSender)
        }
        return (contact.isVerified ? .verifiedContact(contact) : .unverifiedContact(contact), contact.publicIdentity)
    }

    /// What pass 1 measured: the values the signature covers, and the trailer.
    struct BodyDigest: Equatable {
        let ciphertextDigest: [UInt8]
        let chunkCount: UInt64
        let trailer: [UInt8]
    }

    /// Reads the body to the end without decrypting it (FORMAT.md §5.4 framing).
    static func digestBody(from source: any ByteSource) throws -> BodyDigest {
        var reader = ChunkReader(source: source, trailerLength: trailerSize)
        var digest = SHA256()
        var count: UInt64 = 0
        while true {
            guard count < FormatV1.maxChunkCount else { throw CoreFailure(.tooManyChunks) }
            let (sealed, isFinal) = try reader.next()
            digest.update(data: sealed)
            count += 1
            if isFinal {
                return BodyDigest(ciphertextDigest: Array(digest.finalize()), chunkCount: count, trailer: reader.trailer)
            }
        }
    }

    /// HPKE open of your stanza. Every failure (a wrong key, a moved or altered stanza,
    /// another file's wrap context) is the same reason.
    static func unwrap(
        _ stanza: FileHeader.RecipientStanza, context: [UInt8], with key: XWingMLKEM768X25519.PrivateKey
    ) throws -> SymmetricKey {
        do {
            var hpke = try HPKE.Recipient(
                privateKey: key, ciphersuite: ciphersuite, info: Data(context),
                encapsulatedKey: Data(stanza.encapsulatedKey))
            var opened = try hpke.open(stanza.wrappedDataKey, authenticating: stanza.keyID)
            defer { Wipe.data(&opened) }
            guard opened.count == FormatV1.ikmSize else { throw CoreFailure(.unwrapFailed) }
            return SymmetricKey(data: opened)
        } catch {
            throw CoreFailure(.unwrapFailed)
        }
    }

    // MARK: Format helpers

    /// `SHA-256("Chotam v1 wrap context" ‖ bytes 0 ..< 126 ‖ keyID_1 ‖ … ‖ keyID_n)`
    /// (FORMAT.md §6.2): the prelude, the common fields, the sender key ID and the
    /// recipient count, then every stanza's key ID, from the exact header bytes.
    static func wrapContext(rawHeader: [UInt8]) throws -> [UInt8] {
        let fixed = FormatV1.recipientHeaderLength(count: 0)  // 126
        guard rawHeader.count > fixed else { throw CoreFailure(.truncatedHeader) }
        let count = Int(rawHeader[fixed - 1])
        guard rawHeader.count == FormatV1.recipientHeaderLength(count: count) else {
            throw CoreFailure(.headerLengthMismatch)
        }
        var hash = SHA256()
        hash.update(data: wrapContextLabel)
        hash.update(data: Array(rawHeader[0 ..< fixed]))
        for index in 0 ..< count {
            let start = fixed + index * FormatV1.recipientStanzaSize
            hash.update(data: Array(rawHeader[start ..< start + FormatV1.keyIDSize]))
        }
        return Array(hash.finalize())
    }

    /// `"Chotam v1 signature" ‖ headerHash ‖ SHA-256(all sealed chunks) ‖ UInt64BE(n)`
    /// (FORMAT.md §6.3). Fixed-size fields after a fixed label: unambiguous.
    static func signedMessage(headerHash: [UInt8], ciphertextDigest: [UInt8], chunkCount: UInt64) -> [UInt8] {
        var w = ByteWriter()
        w.appendBytes(signatureLabel)
        w.appendBytes(headerHash)
        w.appendBytes(ciphertextDigest)
        w.appendInteger(chunkCount)
        return w.bytes
    }
}
