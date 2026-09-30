/// In-memory model of a v1 header (FORMAT.md §2). None of these fields is
/// secret: salts, nonces, key IDs and the commitment tag are all public.
struct FileHeader: Equatable, Sendable {
    enum Mode: UInt8, Sendable {
        case password = 1
        case recipients = 2
    }

    struct PasswordParameters: Equatable, Sendable {
        var argon2Salt: [UInt8]
        var opsLimit: UInt64
        var memLimit: UInt64
    }

    struct RecipientStanza: Equatable, Sendable {
        var keyID: [UInt8]
        var encapsulatedKey: [UInt8]
        var wrappedDataKey: [UInt8]
    }

    struct RecipientParameters: Equatable, Sendable {
        var senderKeyID: [UInt8]
        var stanzas: [RecipientStanza]
    }

    enum ModeParameters: Equatable, Sendable {
        case password(PasswordParameters)
        case recipients(RecipientParameters)

        var mode: Mode {
            switch self {
            case .password: .password
            case .recipients: .recipients
            }
        }
    }

    var chunkSize: UInt32
    var hkdfSalt: [UInt8]
    var baseNonce: [UInt8]
    var commitment: [UInt8]
    var parameters: ModeParameters

    var mode: Mode { parameters.mode }

    /// The exact encoded length of this header.
    var encodedLength: Int {
        switch parameters {
        case .password:
            FormatV1.passwordHeaderLength
        case .recipients(let r):
            FormatV1.recipientHeaderLength(count: r.stanzas.count)
        }
    }

    /// Checks every field against the v1 rules. Used by the parser (after
    /// decoding) and the encoder (before writing), so both sides agree exactly.
    func validate() throws {
        guard chunkSize == UInt32(FormatV1.chunkSize) else {
            throw CoreFailure(.unsupportedChunkSize)
        }
        guard hkdfSalt.count == FormatV1.hkdfSaltSize,
              baseNonce.count == FormatV1.baseNonceSize,
              commitment.count == FormatV1.commitmentSize
        else { throw CoreFailure(.fieldSizeMismatch) }

        switch parameters {
        case .password(let p):
            guard p.argon2Salt.count == FormatV1.argon2SaltSize else {
                throw CoreFailure(.fieldSizeMismatch)
            }
            guard FormatV1.argon2OpsLimitRange.contains(p.opsLimit),
                  FormatV1.argon2MemLimitRange.contains(p.memLimit)
            else { throw CoreFailure(.argon2ParametersOutOfRange) }

        case .recipients(let r):
            guard r.senderKeyID.count == FormatV1.keyIDSize else {
                throw CoreFailure(.fieldSizeMismatch)
            }
            guard (1...FormatV1.maxRecipients).contains(r.stanzas.count) else {
                throw CoreFailure(.recipientCountOutOfRange)
            }
            var seen = Set<[UInt8]>()
            for stanza in r.stanzas {
                guard stanza.keyID.count == FormatV1.keyIDSize,
                      stanza.encapsulatedKey.count == FormatV1.xwingEncapsulatedKeySize,
                      stanza.wrappedDataKey.count == FormatV1.wrappedDataKeySize
                else { throw CoreFailure(.fieldSizeMismatch) }
                // A recipient listed twice is never produced by our encoder and
                // would make "which stanza is mine" ambiguous: reject it.
                guard seen.insert(stanza.keyID).inserted else {
                    throw CoreFailure(.duplicateRecipient)
                }
            }
        }

        guard encodedLength <= FormatV1.maxHeaderLength else {
            throw CoreFailure(.headerLengthOutOfRange)
        }
    }
}
