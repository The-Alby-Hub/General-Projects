import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The contacts file, `contacts.chotam` (FORMAT.md §10, SECURITY.md D15).
///
/// ```
/// "CHOTAMCF" ‖ version=1 (u16) ‖ owner (32: your encryption key ID) ‖ nonce (12)
///   ‖ AES-256-GCM(contactsKey, nonce, aad = the 54 bytes before it, plaintext) ‖ tag (16)
/// plaintext = count (u16, 0…500)
///   ‖ count × ( verified (u8: 0 or 1) ‖ nameLength (u8, 1…64) ‖ name ‖ pqidLength (u16) ‖ .pqid )
/// ```
///
/// - The contacts key is derived from your passphrase (FORMAT.md §9.6), so only your
///   unlocked identity can read the file or change it. No other program can flip a
///   "verified" flag or swap a contact's key, and the file reveals neither names nor
///   keys. Nothing is kept in the Keychain (SECURITY.md D18).
/// - A fresh random nonce per save. The contacts key is fixed for the identity, so
///   nonces must not repeat: 96 random bits make that negligible for any realistic
///   number of saves.
/// - Not detected: replacing the file with an **older** copy of itself (rollback).
enum ContactsFile {
    static func encode(_ contacts: [Contact], owner: KeyID, key: SymmetricKey) throws -> [UInt8] {
        guard contacts.count <= IdentityFormat.maxContacts else { throw IdentityError.tooManyContacts }
        var plain = ByteWriter()
        plain.appendInteger(UInt16(contacts.count))
        for contact in contacts {
            guard DisplayName.isAcceptable(contact.name) else { throw IdentityError.invalidName }
            let nameBytes = Array(contact.name.utf8)
            plain.appendInteger(UInt8(contact.isVerified ? 1 : 0))
            plain.appendInteger(UInt8(nameBytes.count))
            plain.appendBytes(nameBytes)
            plain.appendInteger(UInt16(contact.publicIdentity.encoded.count))
            plain.appendBytes(contact.publicIdentity.encoded)
        }
        var plaintext = plain.bytes
        defer { Wipe.bytes(&plaintext) }

        let nonce = SecureRandom.bytes(12)
        var header = ByteWriter()
        header.appendBytes(IdentityFormat.contactsMagic)
        header.appendInteger(IdentityFormat.contactsVersion)
        header.appendBytes(owner.bytes)
        header.appendBytes(nonce)
        let sealed = try AES.GCM.seal(
            plaintext, using: key, nonce: try AES.GCM.Nonce(data: nonce), authenticating: header.bytes)
        return header.bytes + [UInt8](sealed.ciphertext) + [UInt8](sealed.tag)
    }

    /// The contacts, in file order. A file that doesn't authenticate, belongs to
    /// another identity or is malformed throws `contactsDamaged`. An entry whose
    /// `.pqid` no longer parses (e.g. a future format change) is skipped and logged,
    /// so one bad entry can't hide the others.
    static func decode(_ bytes: [UInt8], owner: KeyID, key: SymmetricKey) throws -> [Contact] {
        guard bytes.count <= IdentityFormat.contactsMaxFileSize,
              bytes.count >= IdentityFormat.contactsHeaderSize + FormatV1.tagSize
        else { throw CoreFailure(.contactsDamaged) }
        var r = ByteReader(bytes, failure: .contactsDamaged)
        guard try r.readBytes(IdentityFormat.contactsMagic.count) == IdentityFormat.contactsMagic,
              try r.readUInt16() == IdentityFormat.contactsVersion,
              try r.readBytes(32) == owner.bytes
        else { throw CoreFailure(.contactsDamaged) }
        let nonce = try r.readBytes(12)
        let header = Array(bytes.prefix(IdentityFormat.contactsHeaderSize))
        let body = try r.readBytes(r.remaining)

        var plaintext: [UInt8]
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: body.prefix(body.count - FormatV1.tagSize),
                tag: body.suffix(FormatV1.tagSize))
            plaintext = [UInt8](try AES.GCM.open(box, using: key, authenticating: header))
        } catch {
            throw CoreFailure(.contactsDamaged)
        }
        defer { Wipe.bytes(&plaintext) }

        var p = ByteReader(plaintext, failure: .contactsDamaged)
        let count = Int(try p.readUInt16())
        guard count <= IdentityFormat.maxContacts else { throw CoreFailure(.contactsDamaged) }
        var contacts: [Contact] = []
        for _ in 0 ..< count {
            let verified = try p.readUInt8()
            guard verified <= 1 else { throw CoreFailure(.contactsDamaged) }
            let nameLength = Int(try p.readUInt8())
            let nameBytes = try p.readBytes(nameLength)
            let pqidLength = Int(try p.readUInt16())
            guard pqidLength <= IdentityFormat.pqidMaxSize else { throw CoreFailure(.contactsDamaged) }
            let pqid = try p.readBytes(pqidLength)
            // The .pqid is re-verified, signature included, every time it's loaded.
            guard let name = TextRules.strictUTF8(nameBytes), DisplayName.isAcceptable(name),
                  let identity = try? PQIDCodec.decode(pqid)
            else {
                DebugLog.record(.storedRecordDamaged)
                continue
            }
            contacts.append(Contact(name: name, isVerified: verified == 1, publicIdentity: identity))
        }
        guard p.isAtEnd else { throw CoreFailure(.contactsDamaged) }
        return contacts
    }
}
