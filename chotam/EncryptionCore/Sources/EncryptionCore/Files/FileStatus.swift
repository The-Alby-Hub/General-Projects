import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// What a path or an open descriptor refers to, from `stat`/`lstat`/`fstat`.
struct FileStatus {
    enum Kind: Equatable {
        case regular, directory, symbolicLink, other
    }

    /// Device and inode: the same file, whatever path or hard link reaches it.
    struct Identity: Equatable {
        let device: UInt64
        let inode: UInt64
    }

    let kind: Kind
    let identity: Identity
    /// Size in bytes. Recipient-mode decryption checks it hasn't changed between the
    /// two passes (SECURITY.md D19); the hashes are what actually guarantee it.
    let size: Int64

    private init(_ s: stat) {
        // File-type bits (S_IFMT) spelled out, because `mode_t` and the S_IF*
        // constants have different integer types on Darwin and Glibc.
        switch UInt32(s.st_mode) & 0o170000 {
        case 0o100000: kind = .regular
        case 0o040000: kind = .directory
        case 0o120000: kind = .symbolicLink
        default: kind = .other
        }
        identity = Identity(
            device: UInt64(truncatingIfNeeded: s.st_dev),
            inode: UInt64(truncatingIfNeeded: s.st_ino))
        size = Int64(truncatingIfNeeded: s.st_size)
    }

    /// The file behind an open descriptor, so what we check is what we read.
    static func of(descriptor: Int32) -> FileStatus? {
        var s = stat()
        return fstat(descriptor, &s) == 0 ? FileStatus(s) : nil
    }

    /// nil if nothing exists at `url`.
    ///
    /// - Parameter followingLinks: false looks at a symbolic link itself (`lstat`),
    ///   so a link is never mistaken for the file it points to.
    static func lookup(_ url: URL, followingLinks: Bool) throws -> FileStatus? {
        var s = stat()
        let code = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return EINVAL }
            let result = followingLinks ? stat(path, &s) : lstat(path, &s)
            return result == 0 ? 0 : errno
        }
        switch code {
        case 0: return FileStatus(s)
        case ENOENT: return nil
        default: throw FileProblem.posix(code, otherwise: .invalidDestination)
        }
    }
}

/// The input, opened read-only. Chotam never writes to, moves or deletes it.
struct InputFile {
    let handle: FileHandle
    let status: FileStatus

    init(opening url: URL) throws {
        // Checked by path first: opening a folder can succeed on some systems.
        if let status = try? FileStatus.lookup(url, followingLinks: true), status.kind != .regular {
            throw FileProblem.inputNotAFile
        }
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: url)
        } catch {
            throw FileProblem.classify(error, otherwise: .readFailed)
        }
        // Checked again on the open descriptor, in case the path changed meanwhile.
        guard let status = FileStatus.of(descriptor: handle.fileDescriptor), status.kind == .regular else {
            try? handle.close()
            throw FileProblem.inputNotAFile
        }
        self.handle = handle
        self.status = status
    }

    func close() {
        try? handle.close()
    }
}
