import Foundation

/// A pull-based byte stream. Implementations return at most `maxCount` bytes
/// per call, and an empty array only at end of stream.
protocol ByteSource: AnyObject {
    func read(maxCount: Int) throws -> [UInt8]
}

extension ByteSource {
    /// Reads until `count` bytes are collected or the stream ends. Returns fewer
    /// than `count` bytes only at end of stream.
    func readFully(_ count: Int) throws -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(count)
        while result.count < count {
            var piece = try read(maxCount: count - result.count)
            if piece.isEmpty { break }
            result.append(contentsOf: piece)
            Wipe.bytes(&piece)
        }
        return result
    }
}

/// A source that can start again from its first byte. Recipient-mode decryption reads
/// the input twice (SECURITY.md D19): pass 1 checks the signature, pass 2 decrypts.
protocol RewindableSource: ByteSource {
    func rewind() throws
}

/// A push-based byte sink.
protocol ByteSink: AnyObject {
    func write(_ data: Data) throws
}

/// Reads a file through a `FileHandle`, never more than one request at a time.
/// Only regular files reach it (`InputFile`), so it can always seek back to the start.
final class FileHandleSource: RewindableSource {
    private let handle: FileHandle

    init(_ handle: FileHandle) {
        self.handle = handle
    }

    func read(maxCount: Int) throws -> [UInt8] {
        guard maxCount > 0 else { return [] }
        do {
            guard var data = try handle.read(upToCount: maxCount) else { return [] }
            defer { Wipe.data(&data) }
            return [UInt8](data)
        } catch {
            throw CoreFailure(.readFailed)
        }
    }

    func rewind() throws {
        do {
            try handle.seek(toOffset: 0)
        } catch {
            throw CoreFailure(.readFailed)
        }
    }
}

final class FileHandleSink: ByteSink {
    private let handle: FileHandle

    init(_ handle: FileHandle) {
        self.handle = handle
    }

    func write(_ data: Data) throws {
        do {
            try handle.write(contentsOf: data)
        } catch {
            throw CoreFailure(.writeFailed)
        }
    }
}

/// In-memory source, used for headers and in tests.
final class MemorySource: RewindableSource {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    func read(maxCount: Int) throws -> [UInt8] {
        let count = min(max(maxCount, 0), bytes.count - offset)
        defer { offset += count }
        return Array(bytes[offset ..< offset + count])
    }

    func rewind() throws {
        offset = 0
    }
}

/// In-memory sink, used in tests.
final class MemorySink: ByteSink {
    private(set) var bytes: [UInt8] = []

    func write(_ data: Data) throws {
        bytes.append(contentsOf: data)
    }
}

/// Yields `prefix` first, then the bytes of `base`. Prepends the metadata record
/// (FORMAT.md §3) to the file contents without copying the file.
final class PrefixedSource: ByteSource {
    private var prefix: [UInt8]
    private var offset = 0
    private let base: any ByteSource

    init(prefix: [UInt8], base: any ByteSource) {
        self.prefix = prefix
        self.base = base
    }

    func read(maxCount: Int) throws -> [UInt8] {
        if offset < prefix.count {
            let count = min(max(maxCount, 0), prefix.count - offset)
            defer { offset += count }
            return Array(prefix[offset ..< offset + count])
        }
        return try base.read(maxCount: maxCount)
    }
}

// MARK: Progress and cancellation

/// Progress reports and cancellation for one file operation.
///
/// Internal: the public async API (`FileProcessor+Async.swift`, SECURITY.md D28) wires it
/// to a progress closure and to Swift task cancellation. Progress counts bytes read from
/// the input file, so a recipient-mode decryption, which reads the file twice, has a
/// total of twice its size.
struct ProgressHook {
    /// Called after each read with the bytes read so far and the expected total.
    var report: ((_ completed: Int64, _ total: Int64) -> Void)? = nil
    /// Polled before every read and between stages. Returning true stops the operation
    /// with `CoreFailure(.cancelled)`: it unwinds like any other failure, so the temp
    /// file is deleted and the keys and buffers are released and wiped on the way out.
    var isCancelled: (() -> Bool)? = nil
}

final class ProgressMeter {
    let total: Int64
    private(set) var completed: Int64 = 0
    private let hook: ProgressHook

    init(total: Int64, hook: ProgressHook) {
        self.total = max(total, 0)
        self.hook = hook
    }

    /// Throws `.cancelled` if the operation was cancelled.
    func checkpoint() throws {
        if hook.isCancelled?() == true {
            throw CoreFailure(.cancelled)
        }
    }

    func advance(by count: Int) {
        guard count > 0 else { return }
        completed += Int64(count)
        hook.report?(min(completed, total), total)
    }
}

/// Counts what is read from the input and checks for cancellation before every read,
/// so an operation stops within one chunk of being cancelled, in either pass.
final class MeteredSource: RewindableSource {
    private let base: any RewindableSource
    let meter: ProgressMeter

    init(_ base: any RewindableSource, meter: ProgressMeter) {
        self.base = base
        self.meter = meter
    }

    func read(maxCount: Int) throws -> [UInt8] {
        try meter.checkpoint()
        let piece = try base.read(maxCount: maxCount)
        meter.advance(by: piece.count)
        return piece
    }

    func rewind() throws {
        try meter.checkpoint()
        try base.rewind()
    }
}
