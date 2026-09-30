/// Strict encoder and parser for the v1 header (FORMAT.md §2 and §7).
///
/// The parser is written for hostile input: every size is checked before it's
/// used, lengths must match exactly, and trailing bytes are rejected. It only
/// ever throws `CoreFailure`; it never traps.
enum HeaderCodec {
    // MARK: Encoding

    static func encode(_ header: FileHeader) throws -> [UInt8] {
        do {
            try header.validate()
        } catch {
            // On the encrypt side a bad field is a programming error in the
            // caller, reported as one reason rather than the parser's detail.
            throw CoreFailure(.invalidHeaderFields)
        }

        var w = ByteWriter()
        w.appendBytes(FormatV1.magic)
        w.appendInteger(FormatV1.version)
        w.appendInteger(header.mode.rawValue)
        w.appendInteger(UInt32(header.encodedLength))

        w.appendInteger(header.chunkSize)
        w.appendBytes(header.hkdfSalt)
        w.appendBytes(header.baseNonce)
        w.appendBytes(header.commitment)

        switch header.parameters {
        case .password(let p):
            w.appendBytes(p.argon2Salt)
            w.appendInteger(p.opsLimit)
            w.appendInteger(p.memLimit)

        case .recipients(let r):
            w.appendBytes(r.senderKeyID)
            w.appendInteger(UInt8(r.stanzas.count))
            for stanza in r.stanzas {
                w.appendBytes(stanza.keyID)
                w.appendInteger(UInt16(stanza.encapsulatedKey.count))
                w.appendBytes(stanza.encapsulatedKey)
                w.appendInteger(UInt16(stanza.wrappedDataKey.count))
                w.appendBytes(stanza.wrappedDataKey)
            }
        }

        guard w.bytes.count == header.encodedLength else {
            throw CoreFailure(.invalidHeaderFields)
        }
        return w.bytes
    }

    // MARK: Parsing

    /// Validates the 12-byte prelude and returns the declared header length.
    /// This runs before the rest of the header is read, so a hostile length
    /// can't cause a large read or allocation.
    static func parsePrelude(_ prelude: [UInt8]) throws -> (mode: FileHeader.Mode, headerLength: Int) {
        var r = ByteReader(prelude)
        let magic = try r.readBytes(FormatV1.magic.count)
        guard magic == FormatV1.magic else {
            throw CoreFailure(.badMagic)
        }
        let version = try r.readUInt16()
        guard version == FormatV1.version else {
            throw CoreFailure(.unsupportedVersion)
        }
        let modeByte = try r.readUInt8()
        guard let mode = FileHeader.Mode(rawValue: modeByte) else {
            throw CoreFailure(.unknownMode)
        }
        let length = Int(try r.readUInt32())

        switch mode {
        case .password:
            guard length == FormatV1.passwordHeaderLength else {
                throw CoreFailure(.headerLengthMismatch)
            }
        case .recipients:
            let range = FormatV1.recipientHeaderLength(count: 1) ... FormatV1.recipientHeaderLength(count: FormatV1.maxRecipients)
            guard range.contains(length) else {
                throw CoreFailure(.headerLengthOutOfRange)
            }
        }
        guard length <= FormatV1.maxHeaderLength else {
            throw CoreFailure(.headerLengthOutOfRange)
        }
        return (mode, length)
    }

    /// Decodes a complete header. `bytes` must be exactly the header: no more, no less.
    static func decode(_ bytes: [UInt8]) throws -> FileHeader {
        guard bytes.count >= FormatV1.preludeSize else {
            throw CoreFailure(.truncatedHeader)
        }
        let (mode, length) = try parsePrelude(Array(bytes.prefix(FormatV1.preludeSize)))
        guard bytes.count >= length else { throw CoreFailure(.truncatedHeader) }
        guard bytes.count == length else { throw CoreFailure(.trailingHeaderBytes) }

        var r = ByteReader(bytes)
        try r.skip(FormatV1.preludeSize)

        let chunkSize = try r.readUInt32()
        guard chunkSize == UInt32(FormatV1.chunkSize) else {
            throw CoreFailure(.unsupportedChunkSize)
        }
        let hkdfSalt = try r.readBytes(FormatV1.hkdfSaltSize)
        let baseNonce = try r.readBytes(FormatV1.baseNonceSize)
        let commitment = try r.readBytes(FormatV1.commitmentSize)

        let parameters: FileHeader.ModeParameters
        switch mode {
        case .password:
            let salt = try r.readBytes(FormatV1.argon2SaltSize)
            let ops = try r.readUInt64()
            let mem = try r.readUInt64()
            parameters = .password(.init(argon2Salt: salt, opsLimit: ops, memLimit: mem))

        case .recipients:
            let sender = try r.readBytes(FormatV1.keyIDSize)
            let count = Int(try r.readUInt8())
            guard (1...FormatV1.maxRecipients).contains(count) else {
                throw CoreFailure(.recipientCountOutOfRange)
            }
            // The count fixes the exact header length; check it before reading stanzas.
            guard length == FormatV1.recipientHeaderLength(count: count) else {
                throw CoreFailure(.headerLengthMismatch)
            }
            var stanzas: [FileHeader.RecipientStanza] = []
            stanzas.reserveCapacity(count)
            for _ in 0 ..< count {
                let keyID = try r.readBytes(FormatV1.keyIDSize)
                let encLength = Int(try r.readUInt16())
                guard encLength == FormatV1.xwingEncapsulatedKeySize else {
                    throw CoreFailure(.fieldSizeMismatch)
                }
                let enc = try r.readBytes(FormatV1.xwingEncapsulatedKeySize)
                let wrappedLength = Int(try r.readUInt16())
                guard wrappedLength == FormatV1.wrappedDataKeySize else {
                    throw CoreFailure(.fieldSizeMismatch)
                }
                let wrapped = try r.readBytes(FormatV1.wrappedDataKeySize)
                stanzas.append(.init(keyID: keyID, encapsulatedKey: enc, wrappedDataKey: wrapped))
            }
            parameters = .recipients(.init(senderKeyID: sender, stanzas: stanzas))
        }

        guard r.isAtEnd else { throw CoreFailure(.trailingHeaderBytes) }

        let header = FileHeader(
            chunkSize: chunkSize,
            hkdfSalt: hkdfSalt,
            baseNonce: baseNonce,
            commitment: commitment,
            parameters: parameters
        )
        // Range checks (Argon2id limits, duplicate recipients) shared with the encoder.
        try header.validate()
        return header
    }

    /// Reads and decodes the header at the start of `source`.
    ///
    /// Returns the raw bytes as read, because the header hash (FORMAT.md §2.5)
    /// must cover the exact bytes in the file, never a re-encoding.
    static func read(from source: any ByteSource) throws -> (header: FileHeader, raw: [UInt8]) {
        let prelude = try source.readFully(FormatV1.preludeSize)
        guard prelude.count == FormatV1.preludeSize else {
            throw CoreFailure(.truncatedHeader)
        }
        let (_, length) = try parsePrelude(prelude)
        let rest = try source.readFully(length - FormatV1.preludeSize)
        guard rest.count == length - FormatV1.preludeSize else {
            throw CoreFailure(.truncatedHeader)
        }
        let raw = prelude + rest
        return (try decode(raw), raw)
    }
}
