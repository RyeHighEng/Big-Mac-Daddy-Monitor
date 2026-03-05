import SwiftUI
#if canImport(AppKit)
import AppKit
#endif

@main
struct MacMonitorApp: App {
#if canImport(AppKit)
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
#endif
    @StateObject private var viewModel = MonitorViewModel()

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environmentObject(viewModel)
                .frame(minWidth: 1600, minHeight: 860)
                .preferredColorScheme(.dark)
                .tint(AppTheme.cursor)
        }
        .defaultSize(width: 1700, height: 920)
        .windowStyle(.titleBar)

        WindowGroup(id: "history") {
            TrafficHistoryView()
                .environmentObject(viewModel)
                .frame(minWidth: 1600, minHeight: 820)
                .preferredColorScheme(.dark)
                .tint(AppTheme.cursor)
        }
        .defaultSize(width: 1720, height: 900)
        .windowStyle(.titleBar)

        MenuBarExtra {
            MenuBarOverviewView()
                .environmentObject(viewModel)
                .preferredColorScheme(.dark)
                .tint(AppTheme.cursor)
        } label: {
            #if canImport(AppKit)
            Image(nsImage: HamburgerIcon.menuBarImage)
                .renderingMode(.template)
            #else
            Image(systemName: "line.3.horizontal")
            #endif
        }
        .menuBarExtraStyle(.window)
    }
}

#if canImport(AppKit)
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.accessory)
        NSApplication.shared.applicationIconImage = HamburgerIcon.appIconImage()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
#endif
