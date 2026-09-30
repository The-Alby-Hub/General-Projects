// The small records Chotam keeps in its own Keychain items (FORMAT.md §10).
//
// They never leave the Mac, but they are parsed as strictly as anything imported:
// the embedded `.pqid` goes through the full parser again, signature included, so
// a damaged or swapped item is caught instead of trusted.

/// `"CHOTAMME" ‖ version=1 (u16) ‖ signingKeyStorage (u8: 1 = Secure Enclave, 2 = Keychain)
///  ‖ pqidLength (u16) ‖ own .pqid`
struct OwnIdentityRecord: Equatable {
    let signingKeyStorage: KeyStorage
    let publicIdentity: PublicIdentity

    func encode() -> [UInt8] {
        var w = ByteWriter()
        w.appendBytes(IdentityFormat.ownIdentityMagic)
        w.appendInteger(IdentityFormat.ownIdentityVersion)
        w.appendInteger(signingKeyStorage.code)
        w.appendInteger(UInt16(publicIdentity.encoded.count))
        w.appendBytes(publicIdentity.encoded)
        return w.bytes
    }

    static func decode(_ bytes: [UInt8]) throws -> OwnIdentityRecord {
        var r = ByteReader(bytes, failure: .storedRecordDamaged)
        guard try r.readBytes(IdentityFormat.ownIdentityMagic.count) == IdentityFormat.ownIdentityMagic,
              try r.readUInt16() == IdentityFormat.ownIdentityVersion,
              let storage = KeyStorage(code: try r.readUInt8())
        else { throw CoreFailure(.storedRecordDamaged) }
        let length = Int(try r.readUInt16())
        guard length <= IdentityFormat.pqidMaxSize else { throw CoreFailure(.storedRecordDamaged) }
        let pqid = try r.readBytes(length)
        guard r.isAtEnd else { throw CoreFailure(.storedRecordDamaged) }
        return OwnIdentityRecord(signingKeyStorage: storage, publicIdentity: try PQIDCodec.decode(pqid))
    }
}

/// `"CHOTAMCT" ‖ version=1 (u16) ‖ verified (u8: 0 or 1) ‖ nameLength (u8, 1…64) ‖ name
///  ‖ pqidLength (u16) ‖ the contact's .pqid`
struct ContactRecord: Equatable {
    let name: String
    let isVerified: Bool
    let publicIdentity: PublicIdentity

    func encode() throws -> [UInt8] {
        guard DisplayName.isAcceptable(name) else { throw IdentityError.invalidName }
        let nameBytes = Array(name.utf8)
        var w = ByteWriter()
        w.appendBytes(IdentityFormat.contactMagic)
        w.appendInteger(IdentityFormat.contactVersion)
        w.appendInteger(UInt8(isVerified ? 1 : 0))
        w.appendInteger(UInt8(nameBytes.count))
        w.appendBytes(nameBytes)
        w.appendInteger(UInt16(publicIdentity.encoded.count))
        w.appendBytes(publicIdentity.encoded)
        return w.bytes
    }

    static func decode(_ bytes: [UInt8]) throws -> ContactRecord {
        var r = ByteReader(bytes, failure: .storedRecordDamaged)
        guard try r.readBytes(IdentityFormat.contactMagic.count) == IdentityFormat.contactMagic,
              try r.readUInt16() == IdentityFormat.contactVersion
        else { throw CoreFailure(.storedRecordDamaged) }
        let verified = try r.readUInt8()
        guard verified <= 1 else { throw CoreFailure(.storedRecordDamaged) }
        let nameLength = Int(try r.readUInt8())
        guard let name = TextRules.strictUTF8(try r.readBytes(nameLength)), DisplayName.isAcceptable(name) else {
            throw CoreFailure(.storedRecordDamaged)
        }
        let length = Int(try r.readUInt16())
        guard length <= IdentityFormat.pqidMaxSize else { throw CoreFailure(.storedRecordDamaged) }
        let pqid = try r.readBytes(length)
        guard r.isAtEnd else { throw CoreFailure(.storedRecordDamaged) }
        return ContactRecord(name: name, isVerified: verified == 1, publicIdentity: try PQIDCodec.decode(pqid))
    }
}

extension KeyStorage {
    var code: UInt8 {
        switch self {
        case .secureEnclave: 1
        case .keychain: 2
        }
    }

    init?(code: UInt8) {
        switch code {
        case 1: self = .secureEnclave
        case 2: self = .keychain
        default: return nil
        }
    }
}
