import AppKit
import ChotamAppModel

/// Feeds the idle timeout (SECURITY.md D29): key presses, clicks and scrolls in
/// Chotam's own windows count as activity, and the session checks every 15 seconds.
///
/// A local monitor sees only events sent to Chotam: no permission, and nothing typed in
/// other apps. The events are passed on unchanged.
@MainActor
final class ActivityMonitor {
    private var monitor: Any?
    private var timer: Timer?

    init(session: AppSession) {
        monitor = NSEvent.addLocalMonitorForEvents(
            matching: [.keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .scrollWheel]
        ) { [weak session] event in
            MainActor.assumeIsolated { session?.noteActivity() }
            return event
        }

        // In the common run loop modes, so it also fires while a menu or panel is open.
        let timer = Timer(timeInterval: 15, repeats: true) { [weak session] _ in
            MainActor.assumeIsolated { session?.checkIdle() }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }
}
