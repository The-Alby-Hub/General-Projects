#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A fixed-size buffer for secret bytes that Chotam allocates itself: a passphrase's
/// UTF-8 bytes, an Argon2id output, a key seed (SECURITY.md §7.3).
///
/// - The memory is `mlock`ed, so the OS doesn't write it to swap. This is best effort:
///   if the per-process limit is reached, the buffer still works, just unlocked.
/// - It is wiped with `memset_s` (which the compiler may not remove) and unlocked when
///   the buffer is released, on every path, errors included.
/// - It is a class so it is never copied: there is exactly one copy of the bytes.
final class SecretBuffer {
    private let storage: UnsafeMutableRawBufferPointer
    private let isLocked: Bool
    let count: Int

    init(count: Int) {
        precondition(count >= 0)
        self.count = count
        // At least 1 byte, so the pointer is never nil (libsodium wants a valid pointer).
        storage = UnsafeMutableRawBufferPointer.allocate(byteCount: max(count, 1), alignment: 16)
        _ = storage.initializeMemory(as: UInt8.self, repeating: 0)
        isLocked = mlock(storage.baseAddress!, storage.count) == 0
    }

    /// A buffer holding a copy of `bytes`.
    convenience init(copying bytes: UnsafeRawBufferPointer) {
        self.init(count: bytes.count)
        if !bytes.isEmpty {
            storage.copyMemory(from: bytes)
        }
    }

    deinit {
        Wipe.raw(storage)
        if isLocked {
            munlock(storage.baseAddress!, storage.count)
        }
        storage.deallocate()
    }

    /// The bytes. Don't let the pointer escape the closure.
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        // Built from the base address, so it's never nil, even for 0 bytes.
        try body(UnsafeRawBufferPointer(start: storage.baseAddress, count: count))
    }

    func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeMutableRawBufferPointer(start: storage.baseAddress, count: count))
    }

    /// The bytes as a CryptoKit key. CryptoKit copies them into its own storage,
    /// which it zeroes when the key is released.
    var symmetricKey: SymmetricKey {
        withUnsafeBytes { SymmetricKey(data: $0) }
    }

    /// Whether `mlock` succeeded. For tests and the debug log only.
    var isMemoryLocked: Bool { isLocked }
}
