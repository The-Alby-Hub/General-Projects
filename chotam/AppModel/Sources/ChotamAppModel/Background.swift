import Foundation

/// Runs slow, synchronous core calls off the main actor.
///
/// Unlocking or creating an identity runs Argon2id (a few seconds, about 1 GiB). That
/// work goes on its own queue, not on Swift's cooperative thread pool, which shouldn't
/// be blocked for seconds, and never on the main thread.
enum Background {
    private static let queue = DispatchQueue(
        label: "Chotam.AppModel", qos: .userInitiated, attributes: .concurrent)

    static func run<T: Sendable, E: Error>(
        _ work: @escaping @Sendable () throws(E) -> T
    ) async throws(E) -> T {
        let result: Result<T, E> = await withCheckedContinuation { continuation in
            queue.async {
                continuation.resume(returning: Result(catching: work))
            }
        }
        return try result.get()
    }
}
