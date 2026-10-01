import ChotamAppModel
import EncryptionCore
import SwiftUI

/// The main window: Files, My Identity and Contacts.
struct RootView: View {
    enum Section: Hashable {
        case files, identity, contacts
    }

    @Environment(AppSession.self) var session
    @State var section: Section? = .identity

    var body: some View {
        NavigationSplitView {
            List(selection: $section) {
                Label("Files", systemImage: "doc").tag(Section.files)
                Label("My Identity", systemImage: "person.badge.key").tag(Section.identity)
                Label("Contacts", systemImage: "person.2").tag(Section.contacts)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
            .safeAreaInset(edge: .bottom) {
                LockStatusBar()
            }
        } detail: {
            switch section ?? .identity {
            case .files: FilesPlaceholderView()
            case .identity: IdentityScreen()
            case .contacts: ContactsScreen()
            }
        }
        .background(MainWindowConfigurator())
        .task { await session.identity.load() }
        .sheet(isPresented: showingNewPassphrase) {
            PassphraseRevealView()
        }
    }

    /// The new passphrase is a sheet that can only be left by confirming or starting over.
    private var showingNewPassphrase: Binding<Bool> {
        Binding(
            get: {
                if case .newPassphrase = session.identity.state { true } else { false }
            },
            set: { _ in })
    }
}

/// Locked or unlocked, at the bottom of the sidebar, with a Lock button.
struct LockStatusBar: View {
    @Environment(AppSession.self) var session

    var body: some View {
        HStack {
            if session.identity.isUnlocked {
                Label("Unlocked", systemImage: "lock.open.fill")
                    .foregroundStyle(.orange)
                Spacer()
                Button("Lock") { session.identity.lock(reason: .manual) }
                    .keyboardShortcut("l", modifiers: [.command, .control])
            } else {
                Label("Locked", systemImage: "lock.fill")
                    .foregroundStyle(.secondary)
                Spacer()
            }
        }
        .font(.callout)
        .padding(10)
    }
}

/// Phase 6b brings encryption and decryption here.
struct FilesPlaceholderView: View {
    var body: some View {
        ContentUnavailableView(
            "Encrypting and decrypting come next",
            systemImage: "doc.on.doc",
            description: Text("This build covers your identity and contacts. Files arrive in Phase 6b."))
    }
}

/// An error message, in the core's public words (never a path).
struct MessageView: View {
    let text: String?

    var body: some View {
        if let text {
            Label(text, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A "this takes a few seconds" spinner for Argon2id.
struct WorkingView: View {
    let text: String

    var body: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(text).foregroundStyle(.secondary)
        }
    }
}
