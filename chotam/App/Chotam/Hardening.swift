import Darwin
import Foundation

/// Process settings applied at launch (SECURITY.md §8).
enum Hardening {
    static func applyAtLaunch() {
        // No core dumps: a crash must never write the keys in memory to disk. The hard
        // limit is lowered too, so nothing in the process can raise it again.
        var noCore = rlimit(rlim_cur: 0, rlim_max: 0)
        _ = setrlimit(RLIMIT_CORE, &noCore)

        // Don't save windows (and what's typed in them) for restoring after a quit.
        // A registered default lives in memory only; nothing is written to disk.
        UserDefaults.standard.register(defaults: ["NSQuitAlwaysKeepsWindows": false])
    }
}
