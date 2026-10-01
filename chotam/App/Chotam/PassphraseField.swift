import AppKit
import SwiftUI

/// The field the identity passphrase is typed into (SECURITY.md D34, §8).
///
/// An AppKit `NSSecureTextField`: the text is hidden, can't be copied out, and macOS
/// keeps it away from other processes while it's typed. Its content type is left unset
/// (not `.password`) and there's no username field beside it, so macOS has nothing to
/// offer to save. There's deliberately no "show" toggle: a plain field would expose the
/// passphrase to spelling, autocorrection and Writing Tools.
struct PassphraseField: NSViewRepresentable {
    let placeholder: String
    @Binding var text: String
    var onSubmit: () -> Void = {}

    func makeNSView(context: Context) -> NSSecureTextField {
        let field = NSSecureTextField()
        field.placeholderString = placeholder
        field.contentType = nil
        field.isAutomaticTextCompletionEnabled = false
        field.bezelStyle = .roundedBezel
        field.setAccessibilityLabel(placeholder)
        field.delegate = context.coordinator
        field.target = context.coordinator
        field.action = #selector(Coordinator.submit)
        return field
    }

    func updateNSView(_ field: NSSecureTextField, context: Context) {
        context.coordinator.parent = self
        // The model clears the text as soon as an unlock starts.
        if field.stringValue != text {
            field.stringValue = text
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    @MainActor
    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: PassphraseField

        init(_ parent: PassphraseField) {
            self.parent = parent
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSTextField else { return }
            parent.text = field.stringValue
        }

        @objc func submit() {
            parent.onSubmit()
        }
    }
}
