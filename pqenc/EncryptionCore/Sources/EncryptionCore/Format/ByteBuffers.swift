/// Bounds-checked big-endian reader. Every read either succeeds or throws;
/// nothing here can trap on hostile input.
struct ByteReader {
    private let bytes: [UInt8]
    private let failure: CoreFailure.Reason
    private(set) var offset = 0

    init(_ bytes: [UInt8], failure: CoreFailure.Reason = .truncatedHeader) {
        self.bytes = bytes
        self.failure = failure
    }

    var remaining: Int { bytes.count - offset }
    var isAtEnd: Bool { offset == bytes.count }

    mutating func readBytes(_ count: Int) throws -> [UInt8] {
        guard count >= 0, count <= remaining else { throw CoreFailure(failure) }
        let result = Array(bytes[offset ..< offset + count])
        offset += count
        return result
    }

    mutating func skip(_ count: Int) throws {
        guard count >= 0, count <= remaining else { throw CoreFailure(failure) }
        offset += count
    }

    mutating func readUInt8() throws -> UInt8 {
        try readBytes(1)[0]
    }

    mutating func readUInt16() throws -> UInt16 { try readInteger() }
    mutating func readUInt32() throws -> UInt32 { try readInteger() }
    mutating func readUInt64() throws -> UInt64 { try readInteger() }

    private mutating func readInteger<T: FixedWidthInteger & UnsignedInteger>() throws -> T {
        let raw = try readBytes(MemoryLayout<T>.size)
        var value: T = 0
        for byte in raw {
            value = (value << 8) | T(byte)
        }
        return value
    }
}

/// Big-endian writer used by the header encoder and the AAD builder.
struct ByteWriter {
    private(set) var bytes: [UInt8] = []

    mutating func appendBytes(_ other: [UInt8]) {
        bytes.append(contentsOf: other)
    }

    mutating func appendInteger<T: FixedWidthInteger & UnsignedInteger>(_ value: T) {
        Swift.withUnsafeBytes(of: value.bigEndian) { bytes.append(contentsOf: $0) }
    }
}
