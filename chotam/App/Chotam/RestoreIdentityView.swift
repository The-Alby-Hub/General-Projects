import ChotamAppModel
import EncryptionCore
import SwiftUI

/// Sets up your existing identity on this Mac: your `.pqid` (a file, or the text you
/// shared) plus your passphrase, and the key file if it has one.
struct RestoreIdentityView: View {
    @Environment(AppSession.self) var session
    @State var identity: PublicIdentity?
    @State var pasted = ""
    @State var readMessage: String?
    @State var passphrase = ""
    @State var keyFile: URL?

    private var canRestore: Bool {
        guard let identity else { return false }
        return !passphrase.isEmpty && !session.identity.isWorking && (!identity.requiresKeyFile || keyFile != nil)
    }

    var body: some View {
        Form {
            Section {
                if let identity {
                    LabeledContent("Name", value: identity.suggestedName ?? "Unnamed")
                    FingerprintView(fingerprint: identity.fingerprint)
                    Button("Use a Different Identity") { self.identity = nil }
                } else {
                    Button("Choose Your .pqid File…", action: chooseFile)
                    TextField("…or paste your identity text", text: $pasted, axis: .vertical)
                        .lineLimit(3 ... 6)
                        .font(.body.monospaced())
                    Button("Use Pasted Text", action: usePasted)
                        .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    MessageView(text: readMessage)
                }
            } header: {
                Text("1. Your public identity")
            } footer: {
                Text("The .pqid you exported, or that a contact has. It holds no secret.")
            }

            if let identity {
                Section("2. Your passphrase") {
                    PassphraseField(placeholder: "Passphrase", text: $passphrase, onSubmit: restore)
                    if identity.requiresKeyFile {
                        KeyFileRow(keyFile: $keyFile)
                    }
                    Button("Restore", action: restore)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canRestore)
                    if session.identity.isWorking {
                        WorkingView(text: "Checking your passphrase. This takes a few seconds.")
                    }
                    MessageView(text: session.identity.message)
                }
            }
        }
        .formStyle(.grouped)
    }

    private func chooseFile() {
        guard let url = Panels.chooseIdentityFile() else { return }
        read { () throws -> PublicIdentity in try IdentityImport.parse(data: try IdentityFile.read(url)) }
    }

    private func usePasted() {
        read { () throws -> PublicIdentity in try IdentityImport.parse(string: pasted) }
    }

    private func read(_ parse: () throws -> PublicIdentity) {
        do {
            identity = try parse()
            readMessage = nil
            pasted = ""
        } catch {
            readMessage = UserMessage.text(for: error)
        }
    }

    private func restore() {
        guard canRestore, let identity else { return }
        let typed = passphrase
        passphrase = ""
        let keyFile = identity.requiresKeyFile ? self.keyFile : nil
        Task { await session.identity.restore(identity, passphrase: typed, keyFile: keyFile) }
    }
}
