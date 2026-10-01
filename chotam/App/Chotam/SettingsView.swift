import ChotamAppModel
import SwiftUI

/// Chotam's one setting: the idle timeout (SECURITY.md D29).
struct SettingsView: View {
    @Environment(AppSession.self) var session

    var body: some View {
        Form {
            Picker("Lock after", selection: Binding(
                get: { session.idleMinutes },
                set: { session.setIdleMinutes($0) }
            )) {
                ForEach(IdleTimeout.choices, id: \.self) { minutes in
                    Text("\(minutes) minute\(minutes == 1 ? "" : "s") without using Chotam").tag(minutes)
                }
            }
            Text("Chotam also locks your identity when you quit, close its window, lock the screen, start the screen saver, put the Mac to sleep or switch users. Locking removes your keys from memory; unlocking takes a few seconds.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .formStyle(.grouped)
        .frame(width: 460)
    }
}
