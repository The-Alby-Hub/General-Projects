import ChotamAppModel
import EncryptionCore
import SwiftUI

/// A fingerprint as 8 numbered groups of 4, to read aloud (SECURITY.md D5).
struct FingerprintView: View {
    let display: FingerprintDisplay

    init(fingerprint: Fingerprint) {
        display = FingerprintDisplay(groups: fingerprint.groups)
    }

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
            ForEach([0, 4], id: \.self) { start in
                GridRow {
                    ForEach(display.groups[start ..< min(start + 4, display.groups.count)]) { group in
                        HStack(alignment: .firstTextBaseline, spacing: 4) {
                            Text("\(group.number)")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                            Text(group.text)
                                .font(.title3.monospaced())
                        }
                    }
                }
            }
        }
        .textSelection(.enabled)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Fingerprint: \(display.spokenText)")
    }
}
