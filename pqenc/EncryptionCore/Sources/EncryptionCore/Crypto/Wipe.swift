import Foundation

/// Best-effort zeroisation of buffers that held plaintext or key bytes.
///
/// Limits (SECURITY.md §7.3): Swift arrays and `Data` are copy-on-write, so
/// copies made elsewhere by the runtime or Foundation can't be reached from here.
enum Wipe {
    static func bytes(_ buffer: inout [UInt8]) {
        buffer.withUnsafeMutableBytes { zero($0) }
    }

    static func data(_ data: inout Data) {
        data.withUnsafeMutableBytes { zero($0) }
    }

    private static func zero(_ raw: UnsafeMutableRawBufferPointer) {
        guard let base = raw.baseAddress, raw.count > 0 else { return }
        #if canImport(Darwin)
        // memset_s is specified (C11 Annex K) never to be optimised away.
        _ = memset_s(base, raw.count, 0, raw.count)
        #else
        // Linux test build only: a plain fill, which the compiler may elide.
        base.initializeMemory(as: UInt8.self, repeating: 0, count: raw.count)
        #endif
    }
}
