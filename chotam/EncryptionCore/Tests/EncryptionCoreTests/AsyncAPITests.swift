import Foundation
import Synchronization
import XCTest
@testable import EncryptionCore

/// The public async API (SECURITY.md D28): progress reports, and cancelling the calling
/// task, which must clean up exactly like a failure (D24).
final class AsyncAPITests: XCTestCase {
    private let c = Fixtures.chunk
    private let fast = EncryptionMode.password(PasswordFixtures.password, cost: PasswordFixtures.fast)
    private let key = DecryptionMode.password(PasswordFixtures.password)

    // MARK: Helpers

    /// Every progress value reported, in order.
    private final class Reports: Sendable {
        private let values = Mutex<[Double]>([])

        func append(_ value: Double) {
            values.withLock { $0.append(value) }
        }

        var all: [Double] {
            values.withLock { $0 }
        }
    }

    /// Cancels a task from inside its own progress callback, once `fraction` is reached.
    /// The task may not be attached yet when the first report arrives, so a request
    /// made before `attach` is applied by it.
    private final class Canceller: Sendable {
        private struct State {
            var cancel: (@Sendable () -> Void)?
            var requested = false
        }

        private let state = Mutex(State())
        let fraction: Double

        init(at fraction: Double) {
            self.fraction = fraction
        }

        func attach(_ cancel: @escaping @Sendable () -> Void) {
            let now = state.withLock { state -> Bool in
                state.cancel = cancel
                return state.requested
            }
            if now { cancel() }
        }

        func report(_ value: Double) {
            guard value >= fraction else { return }
            let cancel = state.withLock { state -> (@Sendable () -> Void)? in
                state.requested = true
                return state.cancel
            }
            cancel?()
        }
    }

    private func contents(of folder: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: folder.path).sorted()
    }

    private static func encryptResult(
        _ input: URL, to destination: Destination, using mode: EncryptionMode,
        progress: @escaping @Sendable (Double) -> Void
    ) async -> Result<URL, EncryptionError> {
        do {
            return .success(try await FileProcessor.encrypt(input, to: destination, using: mode, progress: progress))
        } catch let error as EncryptionError {
            return .failure(error)
        } catch {
            XCTFail("not an EncryptionError: \(error)")
            return .failure(.unexpected)
        }
    }

    private static func decryptResult(
        _ input: URL, to destination: Destination, using mode: DecryptionMode,
        progress: @escaping @Sendable (Double) -> Void
    ) async -> Result<DecryptedFile, DecryptionError> {
        do {
            return .success(try await FileProcessor.decrypt(input, to: destination, using: mode, progress: progress))
        } catch let error as DecryptionError {
            return .failure(error)
        } catch {
            XCTFail("not a DecryptionError: \(error)")
            return .failure(.failed)
        }
    }

    private func assertIncreasingToOne(_ values: [Double], file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(values.isEmpty, "no progress reported", file: file, line: line)
        XCTAssertEqual(values.last, 1, "progress must end at 1", file: file, line: line)
        XCTAssertTrue(values.allSatisfy { $0 > 0 && $0 <= 1 }, "\(values)", file: file, line: line)
        XCTAssertEqual(values, values.sorted(), "progress went backwards", file: file, line: line)
        XCTAssertEqual(Set(values).count, values.count, "a value was reported twice", file: file, line: line)
    }

    // MARK: Round trips

    func testPasswordRoundTripReportsProgress() async throws {
        let s = try Scratch()
        defer { s.remove() }
        let plaintext = SeededGenerator(seed: 61).bytesArray(5 * c + 17)
        let input = try s.write(plaintext, to: "Report.pdf")
        let out = s.url("out")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: false)

        let sealReports = Reports()
        let encrypted = try await FileProcessor.encrypt(
            input, to: .folder(out), using: fast, progress: { sealReports.append($0) })
        assertIncreasingToOne(sealReports.all)

        let openReports = Reports()
        let opened = try await FileProcessor.decrypt(
            encrypted, to: .file(s.url("Restored.pdf")), using: key, progress: { openReports.append($0) })
        assertIncreasingToOne(openReports.all)
        XCTAssertEqual([UInt8](try Data(contentsOf: opened.url)), plaintext)
        XCTAssertEqual(opened.storedFilename, "Report.pdf")
    }

    /// Two passes: the first ends at about one half, the second at 1.
    func testRecipientRoundTripReportsBothPasses() async throws {
        let alice = try Person("Alice")
        let bob = try Person("Bob")
        let bobAtAlice = try alice.add(bob)
        try bob.add(alice)
        let s = try Scratch()
        defer { s.remove() }
        let plaintext = SeededGenerator(seed: 62).bytesArray(8 * c)
        let input = try s.write(plaintext, to: "Plan.txt")

        let encrypted = try await FileProcessor.encrypt(
            input, to: .file(s.url("Plan.txt.enc")),
            using: .recipients(try confirmedList([bobAtAlice]), signedBy: alice.identity), progress: { _ in })

        let reports = Reports()
        let opened = try await FileProcessor.decrypt(
            encrypted, to: .file(s.url("Opened.txt")), using: .identity(bob.identity),
            progress: { reports.append($0) })
        assertIncreasingToOne(reports.all)
        XCTAssertTrue(reports.all.contains { $0 > 0.4 && $0 <= 0.5 }, "the first pass should end near 0.5")
        XCTAssertEqual([UInt8](try Data(contentsOf: opened.url)), plaintext)
        guard case .verifiedContact(let signer)? = opened.signer else {
            return XCTFail("expected a verified signer, got \(String(describing: opened.signer))")
        }
        XCTAssertEqual(signer.name, "Alice")
    }

    // MARK: Cancellation

    func testCancellingEncryptionLeavesNothing() async throws {
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write(SeededGenerator(seed: 63).bytesArray(40 * c), to: "Big.bin")
        let out = s.url("out")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: false)

        let canceller = Canceller(at: 0.3)
        let mode = fast
        let task = Task {
            await Self.encryptResult(input, to: .folder(out), using: mode, progress: { canceller.report($0) })
        }
        canceller.attach { task.cancel() }
        let result = await task.value

        XCTAssertEqual(result, .failure(.cancelled))
        XCTAssertEqual(try contents(of: out), [], "nothing may be left at the destination")
        XCTAssertEqual(try contents(of: s.folder), ["Big.bin", "out"], "nothing beside the input either")
    }

    func testCancellingEitherDecryptionPassLeavesNothing() async throws {
        let alice = try Person("Alice")
        let bob = try Person("Bob")
        let bobAtAlice = try alice.add(bob)
        try bob.add(alice)
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write(SeededGenerator(seed: 64).bytesArray(40 * c), to: "Big.bin")
        let encrypted = try FileProcessor.encrypt(
            input, to: .file(s.url("Big.bin.enc")),
            using: .recipients(try confirmedList([bobAtAlice]), signedBy: alice.identity))
        let out = s.url("out")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: false)

        // 0.2: in pass 1 (checking the signature); 0.8: in pass 2 (decrypting).
        for fraction in [0.2, 0.8] {
            let canceller = Canceller(at: fraction)
            let identity = bob.identity
            let task = Task {
                await Self.decryptResult(encrypted, to: .folder(out), using: .identity(identity), progress: { canceller.report($0) })
            }
            canceller.attach { task.cancel() }
            let result = await task.value

            XCTAssertEqual(result.failure, .cancelled, "cancelled at \(fraction)")
            XCTAssertEqual(try contents(of: out), [], "nothing at the destination after cancelling at \(fraction)")
        }
        XCTAssertEqual(try contents(of: s.folder), ["Big.bin", "Big.bin.enc", "out"])
    }

    /// A task cancelled before it calls the API never opens the input or creates anything.
    func testAlreadyCancelledTaskDoesNothing() async throws {
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write([1, 2, 3], to: "Small.txt")
        let mode = fast
        let folder = s.folder
        let task = Task { () async -> Result<URL, EncryptionError> in
            withUnsafeCurrentTask { $0?.cancel() }
            return await Self.encryptResult(input, to: .folder(folder), using: mode, progress: { _ in
                XCTFail("a cancelled task must not report progress")
            })
        }
        let result = await task.value
        XCTAssertEqual(result, .failure(.cancelled))
        XCTAssertEqual(try contents(of: s.folder), ["Small.txt"])
    }

    /// The async API reports the same public errors as the synchronous one.
    func testErrorsAreTheSyncAPIErrors() async throws {
        let s = try Scratch()
        defer { s.remove() }
        let input = try s.write([1, 2, 3], to: "Small.txt")
        let weak = await Self.encryptResult(input, to: .folder(s.folder), using: .password("short"), progress: { _ in })
        XCTAssertEqual(weak, .failure(.weakPassword))

        let encrypted = try FileProcessor.encrypt(input, to: .folder(s.folder), using: fast)
        let wrong = await Self.decryptResult(
            encrypted, to: .file(s.url("x.txt")), using: .password("correct horse battery stapler"), progress: { _ in })
        XCTAssertEqual(wrong.failure, .failed)
        XCTAssertFalse(FileManager.default.fileExists(atPath: s.url("x.txt").path))
    }

    // MARK: Throttle

    func testThrottleReportsAtMostEveryStepAndAlwaysTheEnd() {
        var values: [Double] = []
        let throttle = ProgressThrottle(step: 0.1) { values.append($0) }
        for completed in stride(from: Int64(0), through: 1000, by: 7) {
            throttle.update(completed: completed, total: 1000)
        }
        throttle.update(completed: 1000, total: 1000)
        throttle.update(completed: 1000, total: 1000)
        XCTAssertEqual(values.last, 1)
        XCTAssertEqual(values.filter { $0 == 1 }.count, 1, "1 is reported once")
        XCTAssertLessThanOrEqual(values.count, 11)
        for (a, b) in zip(values, values.dropFirst()) where b < 1 {
            XCTAssertGreaterThanOrEqual(b - a, 0.1 - 1e-9)
        }
        XCTAssertFalse(values.contains(0), "0 is never reported")
    }

    func testThrottleClampsOddTotals() {
        var values: [Double] = []
        let throttle = ProgressThrottle { values.append($0) }
        throttle.update(completed: 5, total: 0)
        XCTAssertEqual(values, [1])
        throttle.update(completed: 50, total: 10)
        XCTAssertEqual(values, [1], "never above 1, never twice")
    }
}

private extension SeededGenerator {
    func bytesArray(_ count: Int) -> [UInt8] {
        var copy = self
        return copy.bytes(count)
    }
}

private extension Result {
    var failure: Failure? {
        if case .failure(let error) = self { return error }
        return nil
    }
}
