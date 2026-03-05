import SwiftUI

extension Color {
    init(hex: String) {
        let cleaned = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: cleaned).scanHexInt64(&int)

        let r, g, b: UInt64
        switch cleaned.count {
        case 6:
            (r, g, b) = (int >> 16, int >> 8 & 0xFF, int & 0xFF)
        default:
            (r, g, b) = (255, 255, 255)
        }

        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: 1
        )
    }
}

enum AppTheme {
    static let background = Color(hex: "#130A24")
    static let foreground = Color(hex: "#F9E8FF")
    static let cursor = Color(hex: "#FB9728")
    static let selectionBackground = Color(hex: "#471758")
    static let selectionForeground = Color(hex: "#F9E8FF")

    static let surface = Color(hex: "#2B0D36")
    static let surfaceMuted = Color(hex: "#8A479F")

    static let danger = Color(hex: "#E54529")
    static let info = Color(hex: "#2EFFFF")
    static let success = Color(hex: "#7BFFFF")
    static let warning = Color(hex: "#FFB55E")
    static let pink = Color(hex: "#FE6DBC")
}
