/// Crockford base32 (https://www.crockford.com/base32.html), used for fingerprints.
///
/// The alphabet leaves out I, L, O and U, so no two symbols look or sound alike
/// when read aloud or copied by hand: 5 bits per character.
enum Crockford {
    static let alphabet: [Character] = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// Encodes `bytes`, most significant bit first. The bit count must be a multiple
    /// of 5 (a fingerprint is 160 bits), so there is never padding.
    static func encode(_ bytes: [UInt8]) -> String {
        precondition((bytes.count * 8) % 5 == 0, "Crockford.encode needs whole 5-bit groups")
        var result = ""
        var buffer: UInt32 = 0
        var bits: UInt32 = 0
        for byte in bytes {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                result.append(alphabet[Int((buffer >> bits) & 0x1F)])
            }
            // Keep only the bits not yet written, so the buffer never overflows.
            buffer &= (UInt32(1) << bits) - 1
        }
        return result
    }

    /// Turns what a person typed into canonical symbols, as Crockford specifies:
    /// lowercase is uppercased, O reads as 0, I and L read as 1, and spaces and
    /// hyphens are ignored. Returns nil if anything else is present (including U).
    static func normalise(_ text: String) -> String? {
        var result = ""
        for scalar in text.unicodeScalars {
            switch scalar {
            case " ", "-", "\t":
                continue
            case "O", "o":
                result.append("0")
            case "I", "i", "L", "l":
                result.append("1")
            default:
                guard scalar.isASCII else { return nil }
                let upper = Character(scalar).uppercased()
                guard upper.count == 1, let symbol = upper.first, alphabet.contains(symbol) else {
                    return nil
                }
                result.append(symbol)
            }
        }
        return result
    }
}
