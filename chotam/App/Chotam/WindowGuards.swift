import AppKit
import SwiftUI

/// Excludes the window showing this view from screenshots, screen recording and screen
/// sharing while the view is on screen, then restores it (SECURITY.md D34).
///
/// Best effort: it can't stop a camera, and macOS doesn't promise every capture path
/// honours `NSWindow.sharingType`.
struct CaptureProtection: NSViewRepresentable {
    func makeNSView(context: Context) -> ProtectingView {
        ProtectingView()
    }

    func updateNSView(_ view: ProtectingView, context: Context) {}

    final class ProtectingView: NSView {
        private weak var protectedWindow: NSWindow?
        private var previous: NSWindow.SharingType = .readOnly

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let protectedWindow, protectedWindow !== window {
                protectedWindow.sharingType = previous
                self.protectedWindow = nil
            }
            if let window, protectedWindow == nil {
                previous = window.sharingType
                window.sharingType = .none
                protectedWindow = window
            }
        }
    }
}

/// Configures Chotam's main window once it exists (SECURITY.md D29, §8, D35):
/// - not restorable, so nothing typed in it is archived for after a quit;
/// - no frame autosave;
/// - closing it quits Chotam, which locks the identity, even if Settings is open.
struct MainWindowConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> ConfiguringView {
        ConfiguringView()
    }

    func updateNSView(_ view: ConfiguringView, context: Context) {}

    final class ConfiguringView: NSView {
        private var closeObserver: (any NSObjectProtocol)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window, closeObserver == nil else { return }
            window.isRestorable = false
            _ = window.setFrameAutosaveName("")
            closeObserver = NotificationCenter.default.addObserver(
                forName: NSWindow.willCloseNotification, object: window, queue: .main
            ) { _ in
                MainActor.assumeIsolated { NSApp.terminate(nil) }
            }
        }
    }
}
