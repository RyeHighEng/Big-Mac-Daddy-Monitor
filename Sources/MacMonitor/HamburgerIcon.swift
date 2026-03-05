import SwiftUI
#if canImport(AppKit)
import AppKit
#endif

#if canImport(AppKit)
extension NSBezierPath {
    func addQuadCurve(to end: NSPoint, controlPoint: NSPoint) {
        let start = currentPoint
        let cp1 = NSPoint(
            x: start.x + (2.0 / 3.0) * (controlPoint.x - start.x),
            y: start.y + (2.0 / 3.0) * (controlPoint.y - start.y)
        )
        let cp2 = NSPoint(
            x: end.x + (2.0 / 3.0) * (controlPoint.x - end.x),
            y: end.y + (2.0 / 3.0) * (controlPoint.y - end.y)
        )
        curve(to: end, controlPoint1: cp1, controlPoint2: cp2)
    }
}

private extension NSColor {
    convenience init(hex: String) {
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
            calibratedRed: CGFloat(r) / 255,
            green: CGFloat(g) / 255,
            blue: CGFloat(b) / 255,
            alpha: 1
        )
    }
}

enum HamburgerIcon {
    private static let cachedMenuBarImage: NSImage = image(
        size: 18,
        strokeColor: .labelColor,
        lineWidthScale: 1.0,
        backgroundColor: nil,
        template: true
    )

    private static let cachedAppIconImage: NSImage = image(
        size: 512,
        strokeColor: NSColor(hex: "#F9E8FF"),
        lineWidthScale: 1.25,
        backgroundColor: NSColor(hex: "#130A24"),
        template: false
    )

    static var menuBarImage: NSImage {
        cachedMenuBarImage
    }

    static func appIconImage(size: CGFloat = 512) -> NSImage {
        if size == 512 {
            return cachedAppIconImage
        }
        return image(
            size: size,
            strokeColor: NSColor(hex: "#F9E8FF"),
            lineWidthScale: 1.25,
            backgroundColor: NSColor(hex: "#130A24"),
            template: false
        )
    }

    private static func image(
        size: CGFloat,
        strokeColor: NSColor,
        lineWidthScale: CGFloat,
        backgroundColor: NSColor?,
        template: Bool
    ) -> NSImage {
        let image = NSImage(size: NSSize(width: size, height: size), flipped: true) { rect in
            if let backgroundColor {
                backgroundColor.setFill()
                let background = NSBezierPath(roundedRect: rect, xRadius: rect.width * 0.16, yRadius: rect.height * 0.16)
                background.fill()
            }

            let iconBox: CGFloat = backgroundColor == nil ? size : (size * 0.76)
            let scale = iconBox / 24.0
            let offsetX = (size - (24.0 * scale)) / 2.0
            let offsetY = (size - (24.0 * scale)) / 2.0

            func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
                NSPoint(x: offsetX + x * scale, y: offsetY + y * scale)
            }

            let primary = NSBezierPath()
            primary.lineWidth = 2.0 * scale * lineWidthScale
            primary.lineCapStyle = .round
            primary.lineJoinStyle = .round

            // Lucide hamburger path 1
            primary.move(to: p(12, 16))
            primary.line(to: p(4, 16))
            primary.addQuadCurve(to: p(4, 12), controlPoint: p(2, 14))
            primary.line(to: p(20, 12))
            primary.addQuadCurve(to: p(20, 16), controlPoint: p(22, 14))
            primary.line(to: p(15.75, 16))

            primary.move(to: p(5, 12))
            primary.addQuadCurve(to: p(3, 10), controlPoint: p(3, 12))
            primary.addQuadCurve(to: p(21, 10), controlPoint: p(12, 3))
            primary.addQuadCurve(to: p(19, 12), controlPoint: p(21, 12))

            primary.move(to: p(5, 16))
            primary.addQuadCurve(to: p(3, 18), controlPoint: p(3, 16))
            primary.addQuadCurve(to: p(6, 21), controlPoint: p(3, 21))
            primary.line(to: p(18, 21))
            primary.addQuadCurve(to: p(21, 18), controlPoint: p(21, 21))
            primary.addQuadCurve(to: p(19, 16), controlPoint: p(21, 16))

            // Lucide hamburger path 2
            primary.move(to: p(6.67, 12))
            primary.line(to: p(12.8, 16.6))
            primary.addQuadCurve(to: p(15.6, 16.2), controlPoint: p(14.2, 17.2))
            primary.line(to: p(18.75, 12.0))

            strokeColor.setStroke()
            primary.stroke()
            return true
        }

        image.isTemplate = template
        return image
    }
}
#endif
