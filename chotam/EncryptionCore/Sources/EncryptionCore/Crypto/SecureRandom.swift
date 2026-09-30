#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

enum SecureRandom {
    /// Random bytes from CryptoKit's CSPRNG (SecRandomCopyBytes on Apple
    /// platforms). Used for public per-file values: salts and nonces.
    static func bytes(_ count: Int) -> [UInt8] {
        SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Array($0) }
    }
}
