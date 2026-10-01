import ChotamAppModel
import EncryptionCore
import SwiftUI

/// Your unlocked identity: its fingerprint, exporting it, locking, forgetting.
struct MyIdentityView: View {
    let identity: Identity
    @Environment(AppSession.self) var session
    @State var exportMessage: String?
    @State var copied = false
    @State var confirmingForget = false

    var body: some View {
        Form {
            Section {
                LabeledContent("Name", value: identity.name.isEmpty ? "Unnamed" : identity.name)
                LabeledContent("Key file", value: identity.requiresKeyFile ? "Required to unlock" : "Not used")
            } header: {
                Text("My Identity")
            }

            Section {
                FingerprintView(fingerprint: identity.fingerprint)
            } header: {
                Text("Fingerprint")
            } footer: {
                Text("When a contact imports your identity, read all 8 groups to each other, e.g. over a phone call, so they know it's really yours.")
            }

            Section {
                HStack {
                    Button("Export .pqid File…", action: export)
                    Button(copied ? "Copied" : "Copy as Text") {
                        PublicIdentityCopy.copy(identity.publicIdentity)
                        copied = true
                    }
                }
                MessageView(text: exportMessage)
            } header: {
                Text("Share")
            } footer: {
                Text("Your public identity contains no secret: send it to the people who will encrypt files for you.")
            }

            Section {
                Button("Lock") { session.identity.lock(reason: .manual) }
                Button("Forget This Mac…", role: .destructive) { confirmingForget = true }
            } footer: {
                Text("Chotam also locks when you quit, close this window, lock the screen, start the screen saver, sleep, switch users, or after \(session.idleMinutes) minute\(session.idleMinutes == 1 ? "" : "s") without using Chotam.")
            }
        }
        .formStyle(.grouped)
        .forgetThisMacDialog(isPresented: $confirmingForget)
    }

    private func export() {
        let publicIdentity = identity.publicIdentity
        guard let url = Panels.exportLocation(suggestedName: IdentityFile.exportName(for: publicIdentity)) else { return }
        do {
            try IdentityFile.export(publicIdentity, to: url)
            exportMessage = nil
        } catch {
            exportMessage = UserMessage.text(for: error)
        }
    }
}
