import ChotamAppModel
import EncryptionCore
import SwiftUI

/// The new identity's passphrase, shown once (SECURITY.md D34).
///
/// Numbered words in non-selectable text, no copy button, and the sheet is excluded
/// from screen capture. It can only be left by confirming the words were written down,
/// or by starting over.
struct PassphraseRevealView: View {
    @Environment(AppSession.self) var session
    @State var wroteItDown = false
    @State var confirmingStartOver = false

    var body: some View {
        Group {
            if case .newPassphrase(_, let reveal) = session.identity.state {
                content(reveal)
            }
        }
        .padding(24)
        .frame(width: 560)
        .background(CaptureProtection())
        .interactiveDismissDisabled()
    }

    private func content(_ reveal: PassphraseReveal) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Your passphrase").font(.title2.bold())
            Text("Write these \(reveal.words.count) words on paper, in order. Chotam shows them only now and never stores them. Anyone who has them and your public identity can unlock your identity.")
                .fixedSize(horizontal: false, vertical: true)

            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 10) {
                ForEach(rows(reveal.words), id: \.first?.number) { row in
                    GridRow {
                        ForEach(row) { word in
                            HStack(spacing: 6) {
                                Text("\(word.number).")
                                    .monospacedDigit()
                                    .foregroundStyle(.secondary)
                                Text(word.text)
                                    .font(.title3.monospaced())
                            }
                        }
                    }
                }
            }
            .textSelection(.disabled)
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))

            Text("Case and spacing don't matter when you type it. There's no copy button on purpose: the clipboard can reach other apps and your other devices. This window is hidden from screenshots and screen sharing.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Toggle(reveal.confirmationText, isOn: $wroteItDown)

            HStack {
                Button("Start Over…", role: .destructive) { confirmingStartOver = true }
                Spacer()
                Button("Continue") { session.identity.confirmPassphraseWrittenDown() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!wroteItDown)
            }
        }
        .confirmationDialog("Discard this identity?", isPresented: $confirmingStartOver) {
            Button("Discard and Start Over", role: .destructive) {
                Task { await session.identity.startOver() }
            }
        } message: {
            Text("It's removed from this Mac and these words become useless. You can then create a new identity.")
        }
    }

    /// Two words per row.
    private func rows(_ words: [PassphraseReveal.Word]) -> [[PassphraseReveal.Word]] {
        stride(from: 0, to: words.count, by: 2).map { Array(words[$0 ..< min($0 + 2, words.count)]) }
    }
}
