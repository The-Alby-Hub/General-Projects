import EncryptionCore
import Foundation
import Observation

/// Your identity on this Mac: create, unlock, restore, lock, forget (SECURITY.md D17,
/// D29, D34). The views show `state` and call these methods; nothing else touches the
/// identity.
///
/// - Slow calls (Argon2id: a few seconds, about 1 GiB) run in the background, one at a
///   time (`isWorking`).
/// - **A lock always wins.** A lock that arrives while an unlock or a creation is still
///   deriving keys makes its result be locked and dropped when it arrives.
/// - Locking drops the keys and the contact list.
@MainActor
@Observable
public final class IdentityModel {
    public enum State {
        /// Reading the identity file.
        case loading
        /// No identity on this Mac: create one, or restore yours.
        case noIdentity
        /// The identity file exists but can't be read. The message is the public one.
        case unreadable(String)
        case locked(PublicIdentity)
        /// Just created. The words stay on screen until the user confirms they wrote
        /// them down. A lock meanwhile drops the keys but keeps the words (D34).
        case newPassphrase(PublicIdentity, PassphraseReveal)
        case unlocked(Identity)
    }

    public private(set) var state: State = .loading
    /// True while a slow call runs. Buttons that start another one are disabled.
    public private(set) var isWorking = false
    /// The last error, as public text (UserMessage). The view clears it when shown.
    public var message: String?
    /// Why it was last locked, shown on the unlock screen. Nil after a manual lock.
    public private(set) var lastLockReason: LockReason?
    /// Your contacts, only while unlocked.
    public private(set) var contacts: ContactsModel?

    /// Called after every lock, e.g. to cancel a running recipient-mode operation (D29).
    @ObservationIgnored public var onLock: (@MainActor (LockReason) -> Void)?

    private let store: any IdentityStore
    /// The unlocked identity, or the one just created until it's locked.
    @ObservationIgnored private var current: Identity?
    /// Bumped on every lock, so a derivation that started before it is discarded.
    @ObservationIgnored private var lockGeneration = 0

    public init(store: any IdentityStore) {
        self.store = store
    }

    // MARK: Reading the state

    public var publicIdentity: PublicIdentity? {
        switch state {
        case .locked(let identity), .newPassphrase(let identity, _): identity
        case .unlocked(let identity): identity.publicIdentity
        case .loading, .noIdentity, .unreadable: nil
        }
    }

    public var unlockedIdentity: Identity? {
        if case .unlocked(let identity) = state { identity } else { nil }
    }

    public var isUnlocked: Bool { unlockedIdentity != nil }

    /// Whether any private key is in memory: unlocked, or just created and not locked.
    public var holdsKeys: Bool {
        guard let current else { return false }
        return !current.isLocked
    }

    /// The identity needs its key file to unlock.
    public var requiresKeyFile: Bool { publicIdentity?.requiresKeyFile ?? false }

    // MARK: Loading

    public func load() async {
        let store = self.store
        do {
            let stored = try await Background.run { () throws(IdentityError) -> PublicIdentity? in
                try store.storedIdentity()
            }
            state = stored.map { State.locked($0) } ?? State.noIdentity
        } catch {
            state = .unreadable(UserMessage.text(for: error))
        }
    }

    // MARK: Creating

    /// Creates an identity and shows its passphrase (`state == .newPassphrase`).
    public func create(name: String, keyFile: URL?) async {
        guard case .noIdentity = state, begin() else { return }
        defer { isWorking = false }
        let generation = lockGeneration
        let store = self.store
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let created = try await Background.run { () throws(IdentityError) -> NewIdentity in
                try store.create(name: name, keyFile: keyFile)
            }
            if generation != lockGeneration {
                created.identity.lock()
            } else {
                current = created.identity
            }
            state = .newPassphrase(created.identity.publicIdentity, PassphraseReveal(created.passphrase))
        } catch {
            message = UserMessage.text(for: error)
        }
    }

    /// The user confirmed they wrote the passphrase down: drop it, and carry on unlocked
    /// (or locked, if a lock came in meanwhile).
    public func confirmPassphraseWrittenDown() {
        guard case .newPassphrase(let publicIdentity, _) = state else { return }
        if let identity = current, !identity.isLocked {
            becomeUnlocked(identity)
        } else {
            current = nil
            state = .locked(publicIdentity)
        }
    }

    /// Abandons a just-created identity whose passphrase wasn't written down: removes
    /// it from this Mac, so a new one can be created.
    public func startOver() async {
        guard case .newPassphrase = state else { return }
        await forgetThisMac()
    }

    // MARK: Unlocking

    public func unlock(passphrase: String, keyFile: URL?) async {
        guard case .locked = state, begin() else { return }
        defer { isWorking = false }
        message = nil
        let generation = lockGeneration
        let store = self.store
        do {
            let identity = try await Background.run { () throws(IdentityError) -> Identity in
                try store.unlock(passphrase: passphrase, keyFile: keyFile)
            }
            guard generation == lockGeneration, case .locked = state else {
                identity.lock()
                return
            }
            becomeUnlocked(identity)
        } catch {
            message = UserMessage.text(for: error)
        }
    }

    /// Sets up your existing identity on this Mac from your `.pqid` and passphrase.
    public func restore(_ publicIdentity: PublicIdentity, passphrase: String, keyFile: URL?) async {
        guard case .noIdentity = state, begin() else { return }
        defer { isWorking = false }
        message = nil
        let generation = lockGeneration
        let store = self.store
        do {
            let identity = try await Background.run { () throws(IdentityError) -> Identity in
                try store.restore(publicIdentity, passphrase: passphrase, keyFile: keyFile)
            }
            if generation != lockGeneration {
                identity.lock()
                state = .locked(identity.publicIdentity)
            } else {
                becomeUnlocked(identity)
            }
        } catch {
            message = UserMessage.text(for: error)
        }
    }

    // MARK: Locking and forgetting

    /// Drops every key and the contact list. Safe to call in any state.
    public func lock(reason: LockReason) {
        lockGeneration += 1
        current?.lock()
        current = nil
        contacts = nil
        if case .unlocked(let identity) = state {
            identity.lock()
            state = .locked(identity.publicIdentity)
            lastLockReason = reason == .manual ? nil : reason
        }
        onLock?(reason)
    }

    /// Removes your public identity and contacts from this Mac (it can't delete the
    /// identity itself, SECURITY.md §5.23).
    public func forgetThisMac() async {
        guard begin() else { return }
        defer { isWorking = false }
        lock(reason: .manual)
        let store = self.store
        do {
            try await Background.run { () throws(IdentityError) -> Void in try store.forgetThisMac() }
            state = .noIdentity
            lastLockReason = nil
            message = nil
        } catch {
            message = UserMessage.text(for: error)
            if case .newPassphrase(let publicIdentity, _) = state {
                state = .locked(publicIdentity)
            }
        }
    }

    // MARK: Private

    private func begin() -> Bool {
        guard !isWorking else {
            message = UserMessage.text(for: AppProblem.busy)
            return false
        }
        isWorking = true
        return true
    }

    private func becomeUnlocked(_ identity: Identity) {
        current = identity
        state = .unlocked(identity)
        contacts = ContactsModel(identity: identity)
        lastLockReason = nil
    }
}
