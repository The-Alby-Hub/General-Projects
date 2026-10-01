import ChotamAppModel
import EncryptionCore
import SwiftUI

/// Chotam's one window and its Settings (SECURITY.md D27–D35).
///
/// - The identity lives in the sandbox container (`AppLocations.identityFolder`).
/// - The window isn't restored after a quit, and closing it quits Chotam, which locks
///   the identity (D29).
@main
struct ChotamApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State var session: AppSession

    init() {
        // Before anything else: no core dumps, no saved windows (§8).
        Hardening.applyAtLaunch()
        _session = State(initialValue: AppSession(
            store: IdentityVault(folder: AppLocations.identityFolder), defaults: UserDefaults.standard))
    }

    var body: some Scene {
        Window("Chotam", id: "main") {
            RootView()
                .environment(session)
                .frame(minWidth: 780, minHeight: 540)
                .task { appDelegate.attach(session) }
        }
        .restorationBehavior(.disabled)
        .windowResizability(.contentMinSize)
        .commands {
            // One window only: no "New Window".
            CommandGroup(replacing: .newItem) {}
        }

        Settings {
            SettingsView()
                .environment(session)
        }
        .restorationBehavior(.disabled)
    }
}
