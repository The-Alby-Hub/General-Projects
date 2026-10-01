import ChotamAppModel
import EncryptionCore
import SwiftUI

/// "My Identity": whatever the identity's state calls for.
struct IdentityScreen: View {
    @Environment(AppSession.self) var session

    var body: some View {
        switch session.identity.state {
        case .loading:
            ProgressView()
        case .noIdentity:
            WelcomeView()
        case .unreadable(let message):
            UnreadableIdentityView(message: message)
        case .locked(let publicIdentity):
            UnlockView(publicIdentity: publicIdentity)
        case .newPassphrase:
            ContentUnavailableView(
                "Write down your passphrase", systemImage: "pencil.and.list.clipboard",
                description: Text("Then confirm to continue."))
        case .unlocked(let identity):
            MyIdentityView(identity: identity)
        }
    }
}

/// No identity yet: create one, or restore yours from another Mac.
struct WelcomeView: View {
    enum Choice: Hashable {
        case create, restore
    }

    @State var choice = Choice.create

    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $choice) {
                Text("Create My Identity").tag(Choice.create)
                Text("Restore on This Mac").tag(Choice.restore)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            .padding(.top, 16)
            switch choice {
            case .create: CreateIdentityView()
            case .restore: RestoreIdentityView()
            }
        }
    }
}

struct CreateIdentityView: View {
    @Environment(AppSession.self) var session
    @State var name = ""
    @State var usesKeyFile = false
    @State var keyFile: URL?

    private var canCreate: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && !session.identity.isWorking
            && (!usesKeyFile || keyFile != nil)
    }

    var body: some View {
        Form {
            Section {
                TextField("Your name", text: $name)
            } footer: {
                Text("Shown to contacts who import your identity. They choose what to call you.")
            }

            Section("Optional: a key file") {
                Toggle("Also require a key file to unlock", isOn: $usesKeyFile)
                if usesKeyFile {
                    KeyFileRow(keyFile: $keyFile)
                    Text("Any file that never changes, such as a photo kept on a USB stick. Then a leaked passphrase alone is useless, but without the exact file your identity can never be unlocked again.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }

            Section {
                Label {
                    Text("Chotam will show a passphrase of \(IdentityPassphrase.defaultWordCount) words, once. Write it on paper. **There is no recovery:** if you lose it\(usesKeyFile ? " or the key file" : ""), your identity and every file sent to it are gone.")
                } icon: {
                    Image(systemName: "exclamationmark.triangle")
                }
                Button("Create My Identity") {
                    let keyFile = usesKeyFile ? self.keyFile : nil
                    Task { await session.identity.create(name: name, keyFile: keyFile) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canCreate)
                if session.identity.isWorking {
                    WorkingView(text: "Deriving your keys. This takes a few seconds.")
                }
                MessageView(text: session.identity.message)
            }
        }
        .formStyle(.grouped)
    }
}

/// A key file chooser. The file is used, never remembered (D34).
struct KeyFileRow: View {
    @Binding var keyFile: URL?

    var body: some View {
        HStack {
            Image(systemName: "key")
            Text(keyFile?.lastPathComponent ?? "No key file chosen")
                .foregroundStyle(keyFile == nil ? .secondary : .primary)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Button("Choose…") {
                if let url = Panels.chooseKeyFile() { keyFile = url }
            }
        }
    }
}

/// Unlocks the identity stored on this Mac.
struct UnlockView: View {
    let publicIdentity: PublicIdentity
    @Environment(AppSession.self) var session
    @State var passphrase = ""
    @State var keyFile: URL?
    @State var confirmingForget = false

    private var canUnlock: Bool {
        !passphrase.isEmpty && !session.identity.isWorking
            && (!publicIdentity.requiresKeyFile || keyFile != nil)
    }

    var body: some View {
        Form {
            Section {
                LabeledContent("Identity", value: publicIdentity.suggestedName ?? "Unnamed")
                if let reason = session.identity.lastLockReason {
                    Text(reason.explanation).foregroundStyle(.secondary)
                }
                PassphraseField(placeholder: "Passphrase", text: $passphrase, onSubmit: unlock)
                if publicIdentity.requiresKeyFile {
                    KeyFileRow(keyFile: $keyFile)
                }
                Button("Unlock", action: unlock)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canUnlock)
                if session.identity.isWorking {
                    WorkingView(text: "Unlocking. This takes a few seconds.")
                }
                MessageView(text: session.identity.message)
            } header: {
                Text("Unlock your identity")
            } footer: {
                Text("Type your \(IdentityPassphrase.defaultWordCount)-word passphrase. Case and spacing don't matter.")
            }

            Section {
                Button("Forget This Mac…", role: .destructive) { confirmingForget = true }
                    .disabled(session.identity.isWorking)
            } footer: {
                Text("If you've lost your passphrase, this is the only way to create a new identity here.")
            }
        }
        .formStyle(.grouped)
        .forgetThisMacDialog(isPresented: $confirmingForget)
    }

    private func unlock() {
        guard canUnlock else { return }
        let typed = passphrase
        // D34: the field is emptied as soon as the unlock starts.
        passphrase = ""
        let keyFile = publicIdentity.requiresKeyFile ? self.keyFile : nil
        Task { await session.identity.unlock(passphrase: typed, keyFile: keyFile) }
    }
}

/// The identity file exists but can't be read.
struct UnreadableIdentityView: View {
    let message: String
    @State var confirmingForget = false

    var body: some View {
        ContentUnavailableView {
            Label("Your identity can't be read", systemImage: "exclamationmark.triangle")
        } description: {
            Text(message)
        } actions: {
            Button("Forget This Mac…", role: .destructive) { confirmingForget = true }
        }
        .forgetThisMacDialog(isPresented: $confirmingForget)
    }
}

extension View {
    /// The confirmation for "Forget This Mac", with what it does and doesn't do (§5.23).
    func forgetThisMacDialog(isPresented: Binding<Bool>) -> some View {
        modifier(ForgetThisMacDialog(isPresented: isPresented))
    }
}

private struct ForgetThisMacDialog: ViewModifier {
    @Binding var isPresented: Bool
    @Environment(AppSession.self) var session

    func body(content: Content) -> some View {
        content.confirmationDialog("Forget your identity on this Mac?", isPresented: $isPresented) {
            Button("Forget This Mac", role: .destructive) {
                Task { await session.identity.forgetThisMac() }
            }
        } message: {
            Text("Your public identity and your contacts are removed from this Mac. This doesn't delete the identity: anyone with your passphrase and your .pqid can rebuild it. Files sent to it can't be opened here until you restore it.")
        }
    }
}
