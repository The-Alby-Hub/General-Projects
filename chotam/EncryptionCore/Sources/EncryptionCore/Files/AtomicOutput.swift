import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A byte sink that writes to a temp file and only ever puts it in place whole
/// (SECURITY.md D9).
///
/// - The temp file is created lazily, on the first write or at `commit`, so a wrong
///   password or a weak one never creates anything.
/// - It goes in a private folder from `FileManager.url(for: .itemReplacementDirectory, …)`
///   on the destination's volume. The sandbox allows that folder even when only the
///   destination file itself was granted. If the system can't provide one, it goes
///   in the destination folder as a hidden `.chotam-<UUID>.tmp`.
/// - `commit` moves it into place atomically. A new output uses an exclusive rename
///   that fails if anything appeared at that name. An existing output is replaced
///   only when the caller allowed it, with `replaceItemAt`.
/// - `discard` (always called in a `defer`) closes and deletes whatever is left.
///   So on any failure the destination is exactly as it was.
final class AtomicOutput: ByteSink {
    /// Test hooks. Errors thrown by them are reported as `FileProblem.writeFailed`,
    /// like a real write error.
    struct Hooks {
        var onTempCreated: ((URL) -> Void)? = nil
        /// Called before each write with the number of bytes already written.
        var beforeWrite: ((Int) throws -> Void)? = nil
        var beforeCommit: (() throws -> Void)? = nil
    }

    enum Target {
        /// Exactly this path. If something is there, it's replaced only if allowed.
        case file(URL, replacingExisting: Bool)
        /// The first of `names` that's free in `folder`. Never replaces anything.
        case firstFree(in: URL, names: [String])
    }

    private let folder: URL
    private let hooks: Hooks
    private var tempDirectory: URL?
    private var tempFile: URL?
    private var handle: FileHandle?
    private var bytesWritten = 0

    /// - Parameter folder: Where the output will go; picks the volume for the temp file.
    init(folder: URL, hooks: Hooks = Hooks()) {
        self.folder = folder
        self.hooks = hooks
    }

    deinit {
        discard()
    }

    func write(_ data: Data) throws {
        let handle = try openIfNeeded()
        do {
            try hooks.beforeWrite?(bytesWritten)
        } catch {
            throw FileProblem.writeFailed
        }
        do {
            try handle.write(contentsOf: data)
        } catch {
            throw FileProblem.classify(error, otherwise: .writeFailed)
        }
        bytesWritten += data.count
    }

    /// Flushes the temp file to disk and moves it into place. Returns the final URL.
    func commit(to target: Target) throws -> URL {
        // An empty result (an empty decrypted file) still needs a file.
        let handle = try openIfNeeded()
        do {
            try hooks.beforeCommit?()
        } catch {
            throw FileProblem.writeFailed
        }
        try Self.flush(handle)
        do {
            try handle.close()
        } catch {
            throw FileProblem.writeFailed
        }
        self.handle = nil
        guard let tempFile else { throw FileProblem.writeFailed }

        switch target {
        case .file(let destination, let replacingExisting):
            if try Self.moveExclusively(tempFile, to: destination) {
                return destination
            }
            guard replacingExisting else { throw FileProblem.outputExists }
            // Re-checked here, not only before starting: never replace a folder or
            // follow a link that appeared in the meantime.
            guard try FileStatus.lookup(destination, followingLinks: false)?.kind == .regular else {
                throw FileProblem.invalidDestination
            }
            return try Self.replace(destination, with: tempFile)

        case .firstFree(let folder, let names):
            for name in names {
                let candidate = try OutputNaming.url(for: name, in: folder)
                if try Self.moveExclusively(tempFile, to: candidate) {
                    return candidate
                }
            }
            throw FileProblem.outputExists
        }
    }

    /// Closes and deletes the temp file and its private folder, if they still exist.
    /// Safe to call more than once, and after a successful `commit`.
    func discard() {
        if let handle {
            try? handle.close()
            self.handle = nil
        }
        if let tempFile {
            _ = tempFile.withUnsafeFileSystemRepresentation { path in
                path.map { unlink($0) }
            }
            self.tempFile = nil
        }
        if let tempDirectory {
            // rmdir, not a recursive delete: it only removes the folder if it's empty,
            // so nothing but our own file can ever be deleted here.
            _ = tempDirectory.withUnsafeFileSystemRepresentation { path in
                path.map { rmdir($0) }
            }
            self.tempDirectory = nil
        }
    }

    // MARK: Temp file

    private func openIfNeeded() throws -> FileHandle {
        if let handle { return handle }
        let name = "chotam-\(UUID().uuidString).tmp"
        var descriptor: Int32 = -1

        if let directory = try? FileManager.default.url(
            for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: folder, create: true)
        {
            let file = directory.appendingPathComponent(name, isDirectory: false)
            tempDirectory = directory
            if let fd = try? Self.createExclusively(file) {
                descriptor = fd
                tempFile = file
            } else {
                discard()
            }
        }
        if descriptor < 0 {
            let file = folder.appendingPathComponent("." + name, isDirectory: false)
            descriptor = try Self.createExclusively(file)
            tempFile = file
        }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        self.handle = handle
        if let tempFile {
            hooks.onTempCreated?(tempFile)
        }
        return handle
    }

    /// Creates a new file that nobody else can have opened: O_EXCL fails if the name
    /// exists (including as a symbolic link). Mode 0600, because a decryption's temp
    /// file holds plaintext that isn't fully verified yet. The output keeps this mode.
    private static func createExclusively(_ url: URL) throws -> Int32 {
        let result = url.withUnsafeFileSystemRepresentation { path -> (fd: Int32, error: Int32) in
            guard let path else { return (-1, EINVAL) }
            let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            return (fd, fd < 0 ? errno : 0)
        }
        guard result.fd >= 0 else {
            throw FileProblem.posix(result.error, otherwise: .writeFailed)
        }
        return result.fd
    }

    /// Makes sure the bytes are on disk before the rename makes them visible, so a
    /// power cut can't leave an empty or partial file under the final name.
    private static func flush(_ handle: FileHandle) throws {
        let fd = handle.fileDescriptor
        #if canImport(Darwin)
        // On macOS, fsync only reaches the drive's cache; F_FULLFSYNC flushes the
        // drive too. Some file systems (network, FAT) don't support it: then fsync.
        if fcntl(fd, F_FULLFSYNC) == 0 { return }
        #endif
        guard fsync(fd) == 0 else { throw FileProblem.writeFailed }
    }

    // MARK: Moving into place

    /// Moves `source` to `destination` only if nothing exists there, atomically: there
    /// is no gap between checking and renaming for another file to appear in.
    /// Returns false if something already exists at `destination`.
    private static func moveExclusively(_ source: URL, to destination: URL) throws -> Bool {
        #if canImport(Darwin)
        let renameCode = posixCall(source, destination) { from, to in
            renamex_np(from, to, UInt32(RENAME_EXCL))
        }
        switch renameCode {
        case 0:
            return true
        case EEXIST:
            return false
        case ENOTSUP, EINVAL:
            break  // This file system can't do RENAME_EXCL: use a hard link instead.
        default:
            throw FileProblem.posix(renameCode, otherwise: .writeFailed)
        }
        #endif
        // link() also fails with EEXIST if the name is taken, so it's an exclusive
        // create too. The temp name is then unlinked (or removed by `discard`).
        let linkCode = posixCall(source, destination) { from, to in link(from, to) }
        switch linkCode {
        case 0:
            _ = source.withUnsafeFileSystemRepresentation { path in path.map { unlink($0) } }
            return true
        case EEXIST:
            return false
        default:
            throw FileProblem.posix(linkCode, otherwise: .writeFailed)
        }
    }

    /// Atomically replaces an existing regular file.
    private static func replace(_ destination: URL, with source: URL) throws -> URL {
        #if canImport(Darwin)
        do {
            // `.usingNewMetadataOnly`: the old file's tags, quarantine flag or download
            // origin must not be attached to the new contents.
            return try FileManager.default.replaceItemAt(
                destination, withItemAt: source, backupItemName: nil,
                options: [.usingNewMetadataOnly]) ?? destination
        } catch {
            throw FileProblem.classify(error, otherwise: .writeFailed)
        }
        #else
        // Linux (tests only): rename(2) atomically replaces the destination.
        let code = posixCall(source, destination) { from, to in rename(from, to) }
        guard code == 0 else { throw FileProblem.posix(code, otherwise: .writeFailed) }
        return destination
        #endif
    }

    /// Runs a two-path system call; returns 0 on success, otherwise its errno.
    private static func posixCall(
        _ first: URL, _ second: URL,
        _ call: (UnsafePointer<CChar>, UnsafePointer<CChar>) -> Int32
    ) -> Int32 {
        first.withUnsafeFileSystemRepresentation { a -> Int32 in
            second.withUnsafeFileSystemRepresentation { b -> Int32 in
                guard let a, let b else { return EINVAL }
                return call(a, b) == 0 ? 0 : errno
            }
        }
    }
}
