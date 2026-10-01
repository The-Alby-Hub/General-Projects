import ChotamAppModel
import EncryptionCore
import SwiftUI

/// Names a contact before adding it. It always starts unverified (D16).
struct ImportContactSheet: View {
    let model: ContactsModel
    let pending: PendingContact
    let onDone: (Contact?) -> Void
    @State var name: String

    init(model: ContactsModel, pending: PendingContact, onDone: @escaping (Contact?) -> Void) {
        self.model = model
        self.pending = pending
        self.onDone = onDone
        _name = State(initialValue: pending.suggestedName)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Import a contact").font(.title2.bold())
            TextField("Name", text: $name)
            if !pending.suggestedName.isEmpty {
                Text("They call themselves “\(pending.suggestedName)”. Anyone can write any name in an identity; only the fingerprint tells you whose it is.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            GroupBox("Fingerprint") {
                FingerprintView(fingerprint: pending.publicIdentity.fingerprint)
                    .padding(6)
            }
            Text("The contact starts **not verified**. Compare all 8 groups with them, then mark them as verified.")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            MessageView(text: model.message)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onDone(nil) }
                    .keyboardShortcut(.cancelAction)
                Button("Add Contact") {
                    if let added = model.add(pending, name: name) { onDone(added) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 520)
    }
}

/// Pasting the text form of an identity (public, Base64).
struct PasteIdentitySheet: View {
    let model: ContactsModel
    let onFound: (PendingContact?) -> Void
    @State var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Paste an identity").font(.title2.bold())
            Text("Paste the text your contact sent you. It contains no secret.")
                .foregroundStyle(.secondary)
            TextEditor(text: $text)
                .font(.body.monospaced())
                .frame(height: 160)
                .overlay(RoundedRectangle(cornerRadius: 4).stroke(.separator))
            MessageView(text: model.message)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onFound(nil) }
                    .keyboardShortcut(.cancelAction)
                Button("Continue") {
                    if let found = model.prepareImport(string: text) { onFound(found) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 520)
    }
}

/// Comparing fingerprints before marking a contact verified (D5, §5.20): read all 8
/// groups aloud, or type in what they read out.
struct CompareFingerprintSheet: View {
    let contact: Contact
    let onVerified: () -> Void
    let onCancel: () -> Void
    @State var typed = ""

    private var match: FingerprintMatch {
        FingerprintMatch(typed: typed) { contact.fingerprint.matches($0) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Compare fingerprints with \(contact.name)").font(.title2.bold())
            Text("Over a channel you trust, such as a phone or video call, have \(contact.name) read out their fingerprint from Chotam's My Identity. Check every group, 1 to 8.")
                .fixedSize(horizontal: false, vertical: true)
            GroupBox("What Chotam has for \(contact.name)") {
                FingerprintView(fingerprint: contact.fingerprint)
                    .padding(6)
            }
            TextField("Optional: type what they read out", text: $typed)
                .font(.body.monospaced())
            switch match {
            case .notTyped:
                EmptyView()
            case .matches:
                Label("All 32 characters match.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            case .doesNotMatch:
                Label("It doesn't match. Don't mark this contact as verified: the identity may not be theirs.",
                      systemImage: "xmark.octagon.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Button("They Match: Mark as Verified", action: onVerified)
                    .disabled(match == .doesNotMatch)
            }
        }
        .padding(24)
        .frame(width: 560)
    }
}
