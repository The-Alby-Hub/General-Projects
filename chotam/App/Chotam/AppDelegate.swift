import AppKit
import ChotamAppModel

/// Connects the session to what only AppKit sees: quitting, system lock events and
/// input in Chotam's windows (SECURITY.md D29).
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var session: AppSession?
    private var lockEvents: SystemLockEvents?
    private var activity: ActivityMonitor?

    func attach(_ session: AppSession) {
        guard self.session == nil else { return }
        self.session = session
        lockEvents = SystemLockEvents { [weak session] reason in
            session?.systemEvent(reason)
        }
        activity = ActivityMonitor(session: session)
    }

    /// Closing the window quits Chotam (D29); `MainWindowConfigurator` also quits when
    /// the main window closes while Settings is still open.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// Lock on quit: CryptoKit zeroes the keys as they're released.
    func applicationWillTerminate(_ notification: Notification) {
        session?.systemEvent(.quit)
    }
}
