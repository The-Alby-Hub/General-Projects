/// Comparison for secret-dependent values (e.g. the key-commitment tag).
enum ConstantTime {
    /// Returns whether `a` and `b` are equal without an early exit.
    ///
    /// Lengths are public and compared normally. Contents are XOR-accumulated
    /// over the full length with no data-dependent branch. Swift gives no formal
    /// constant-time guarantee for generated code; `@inline(never)` keeps the
    /// optimiser from specialising this into a caller. See SECURITY.md §7.2.
    @inline(never)
    static func equals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for i in 0 ..< a.count {
            difference |= a[i] ^ b[i]
        }
        return difference == 0
    }
}
