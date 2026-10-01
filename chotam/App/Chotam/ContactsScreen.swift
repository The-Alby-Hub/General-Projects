import ChotamAppModel
import EncryptionCore
import SwiftUI

/// "Contacts": only while unlocked, since the list is encrypted with your identity.
struct ContactsScreen: View {
    @Environment(AppSession.self) var session

    var body: some View {
        if let contacts = session.identity.contacts {
            ContactsView(model: contacts)
        } else {
            ContentUnavailableView(
                "Contacts are locked", systemImage: "lock",
                description: Text("Unlock your identity in My Identity to see your contacts."))
        }
    }
}

struct ContactsView: View {
    let model: ContactsModel
    @State var selection: Contact.ID?
    @State var pending: PendingContact?
    @State var pasting = false

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                List(model.contacts, selection: $selection) { contact in
                    ContactRow(contact: contact)
                }
                .overlay {
                    if model.contacts.isEmpty {
                        ContentUnavailableView(
                            "No contacts yet", systemImage: "person.2",
                            description: Text("Import a contact's .pqid file, or paste the text they sent you."))
                    }
                }
                Divider()
                HStack {
                    Button("Import File…", action: importFile)
                    Button("Paste…") { pasting = true }
                    Spacer()
                }
                .padding(8)
            }
            .frame(minWidth: 240, idealWidth: 260, maxWidth: 320)

            Divider()

            Group {
                if let id = selection, let contact = model.contact(id: id) {
                    ContactDetailView(model: model, contact: contact)
                } else {
                    ContentUnavailableView("Select a contact", systemImage: "person")
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .safeAreaInset(edge: .top) {
            MessageView(text: model.message)
                .padding(.horizontal)
        }
        .sheet(item: pendingItem) { item in
            ImportContactSheet(model: model, pending: item.pending) { added in
                pending = nil
                if let added { selection = added.id }
            }
        }
        .sheet(isPresented: $pasting) {
            PasteIdentitySheet(model: model) { found in
                pasting = false
                pending = found
            }
        }
    }

    private func importFile() {
        guard let url = Panels.chooseIdentityFile() else { return }
        do {
            pending = model.prepareImport(data: try IdentityFile.read(url))
        } catch {
            model.message = UserMessage.text(for: error)
        }
    }

    /// `.sheet(item:)` needs an Identifiable.
    private struct PendingItem: Identifiable {
        let pending: PendingContact
        var id: Fingerprint { pending.publicIdentity.fingerprint }
    }

    private var pendingItem: Binding<PendingItem?> {
        Binding(
            get: { pending.map(PendingItem.init) },
            set: { pending = $0?.pending })
    }
}

struct ContactRow: View {
    let contact: Contact

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(contact.name)
                Spacer()
                VerificationBadge(isVerified: contact.isVerified)
            }
            Text(contact.fingerprint.groups.prefix(2).joined(separator: " ") + " …")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

struct VerificationBadge: View {
    let isVerified: Bool

    var body: some View {
        if isVerified {
            Label("Verified", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
        } else {
            Label("Not verified", systemImage: "questionmark.circle")
                .foregroundStyle(.orange)
        }
    }
}

struct ContactDetailView: View {
    let model: ContactsModel
    let contact: Contact
    @State var newName = ""
    @State var comparing = false
    @State var confirmingRemove = false

    var body: some View {
        Form {
            Section {
                LabeledContent("Name", value: contact.name)
                LabeledContent("Status") { VerificationBadge(isVerified: contact.isVerified) }
                if let suggested = contact.publicIdentity.suggestedName, suggested != contact.name {
                    LabeledContent("Calls themselves", value: suggested)
                }
            }

            Section {
                FingerprintView(fingerprint: contact.fingerprint)
                Button(contact.isVerified ? "Compare Again…" : "Compare Fingerprints…") { comparing = true }
            } header: {
                Text("Fingerprint")
            } footer: {
                Text(contact.isVerified
                    ? "You confirmed this fingerprint with \(contact.name)."
                    : "Until you compare all 8 groups with \(contact.name), you can't be sure this identity is theirs. Encrypting to an unverified contact asks for confirmation.")
            }

            Section("Rename") {
                HStack {
                    TextField("New name", text: $newName)
                    Button("Rename") {
                        if model.rename(contact, to: newName) != nil { newName = "" }
                    }
                    .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }

            Section {
                Button("Remove Contact…", role: .destructive) { confirmingRemove = true }
            } footer: {
                Text("Files they sign will no longer open, and you can't encrypt to them.")
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $comparing) {
            CompareFingerprintSheet(contact: contact) {
                comparing = false
                model.markVerified(contact)
            } onCancel: {
                comparing = false
            }
        }
        .confirmationDialog("Remove \(contact.name)?", isPresented: $confirmingRemove) {
            Button("Remove", role: .destructive) { model.remove(contact) }
        } message: {
            Text("You can import them again later; they'll start unverified.")
        }
    }
}
