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

/// A push-based byte sink.
protocol ByteSink: AnyObject {
    func write(_ data: Data) throws
}

/// Reads a file through a `FileHandle`, never more than one request at a time.
final class FileHandleSource: ByteSource {
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
final class MemorySource: ByteSource {
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
