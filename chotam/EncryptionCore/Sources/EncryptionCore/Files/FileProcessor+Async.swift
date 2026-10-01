import Foundation
import Synchronization

// MARK: Progress and cancellation (SECURITY.md D28)

extension FileProcessor {
    /// Encrypts `input` like `encrypt(_:to:using:)`, reporting progress, and stops if
    /// the calling `Task` is cancelled.
    ///
    /// - Parameter progress: Called with the fraction done, from 0 to 1 (bytes read of
    ///   the file's size), at most once per 0.1 %, on a background queue.
    /// - Cancelling the calling task stops the operation before its next read, and
    ///   unwinds exactly like a failure: the temp file is deleted, nothing is left at
    ///   the destination, keys and buffers are released and wiped (SECURITY.md D24).
    ///   It then throws `.cancelled`. Argon2id isn't interrupted: it finishes first.
    /// - The work runs on its own queue, so a long operation never blocks Swift's
    ///   cooperative thread pool.
    public static func encrypt(
        _ input: URL, to destination: Destination, using mode: EncryptionMode,
        progress: @escaping @Sendable (Double) -> Void
    ) async throws(EncryptionError) -> URL {
        let result = await runCancellably(
            cancelled: EncryptionError.cancelled,
            progress: progress
        ) { hook in
            Result { () throws(EncryptionError) -> URL in
                try encrypt(input, to: destination, using: mode, hooks: AtomicOutput.Hooks(), progress: hook)
            }
        }
        return try result.get()
    }

    /// Decrypts `input` like `decrypt(_:to:using:)`, reporting progress, and stops if
    /// the calling `Task` is cancelled.
    ///
    /// - Parameter progress: Called with the fraction done, from 0 to 1, at most once
    ///   per 0.1 %, on a background queue. A recipient-mode file is read twice
    ///   (SECURITY.md D19), so the first pass ends at 0.5.
    /// - Cancelling works as for `encrypt(_:to:using:progress:)`, in either pass.
    public static func decrypt(
        _ input: URL, to destination: Destination, using mode: DecryptionMode,
        progress: @escaping @Sendable (Double) -> Void
    ) async throws(DecryptionError) -> DecryptedFile {
        let result = await runCancellably(
            cancelled: DecryptionError.cancelled,
            progress: progress
        ) { hook in
            Result { () throws(DecryptionError) -> DecryptedFile in
                try decrypt(input, to: destination, using: mode, hooks: AtomicOutput.Hooks(), progress: hook)
            }
        }
        return try result.get()
    }

    /// Runs `work` on the work queue with a hook wired to `progress` and to the calling
    /// task's cancellation. A task cancelled before it starts never opens anything.
    private static func runCancellably<Success: Sendable, Failure: Error>(
        cancelled: Failure,
        progress: @escaping @Sendable (Double) -> Void,
        work: @escaping @Sendable (ProgressHook) -> Result<Success, Failure>
    ) async -> Result<Success, Failure> {
        let flag = CancellationFlag()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Result<Success, Failure>, Never>) in
                AsyncWork.queue.async {
                    guard !flag.isSet else {
                        continuation.resume(returning: .failure(cancelled))
                        return
                    }
                    let throttle = ProgressThrottle(report: progress)
                    let hook = ProgressHook(
                        report: { completed, total in throttle.update(completed: completed, total: total) },
                        isCancelled: { flag.isSet })
                    continuation.resume(returning: work(hook))
                }
            }
        } onCancel: {
            flag.set()
        }
    }
}

/// Where the async API's operations run: not Swift's cooperative pool, which must not
/// be blocked by minutes of file work and Argon2id.
private enum AsyncWork {
    static let queue = DispatchQueue(label: "Chotam.FileProcessor", qos: .userInitiated, attributes: .concurrent)
}

/// Set by the task's cancellation handler, read by the operation before every read.
final class CancellationFlag: Sendable {
    private let value = Atomic<Bool>(false)

    func set() {
        value.store(true, ordering: .relaxed)
    }

    var isSet: Bool {
        value.load(ordering: .relaxed)
    }
}

/// Turns byte counts into a fraction and passes it on only when it has grown by at
/// least `step`, or reached 1, so a large file doesn't produce millions of reports.
/// Used by one operation, on one queue.
final class ProgressThrottle {
    private let step: Double
    private let report: (Double) -> Void
    private var last: Double = 0

    init(step: Double = 0.001, report: @escaping (Double) -> Void) {
        self.step = step
        self.report = report
    }

    func update(completed: Int64, total: Int64) {
        let fraction = total > 0 ? min(1, max(0, Double(completed) / Double(total))) : 1
        guard fraction > last, fraction >= 1 || fraction - last >= step else { return }
        last = fraction
        report(fraction)
    }
}
