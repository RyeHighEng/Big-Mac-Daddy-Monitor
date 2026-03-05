import SwiftUI
import AppKit

struct MenuBarOverviewView: View {
    @EnvironmentObject private var viewModel: MonitorViewModel
    @Environment(\.openWindow) private var openWindow

    private var recentConnections: [NetworkConnection] {
        viewModel.connections
            .sorted { $0.capturedAt > $1.capturedAt }
            .prefix(8)
            .map { $0 }
    }

    var body: some View {
        ZStack {
            AppTheme.background.ignoresSafeArea()

            VStack(alignment: .leading, spacing: 10) {
                Text("Mac Daddy Monitor")
                    .font(.system(size: 14, weight: .bold, design: .rounded))

                HStack(spacing: 8) {
                    chip("Conn", "\(viewModel.connections.count)", AppTheme.info)
                    chip("Susp", "\(viewModel.suspiciousCount)", AppTheme.danger)
                    chip("CPU", Formatters.percentString(viewModel.summary.cpuPercent), AppTheme.success)
                    chip(
                        "Net",
                        Formatters.speedMiniString(
                            downloadBytesPerSecond: viewModel.summary.downloadBytesPerSecond,
                            uploadBytesPerSecond: viewModel.summary.uploadBytesPerSecond
                        ),
                        AppTheme.info
                    )
                }

                Text("Memory: \(Formatters.bytesString(viewModel.summary.usedMemoryBytes)) / \(Formatters.bytesString(viewModel.summary.totalMemoryBytes))")
                    .font(.system(size: 11, weight: .medium, design: .rounded))
                    .foregroundStyle(AppTheme.selectionForeground.opacity(0.8))

                Divider()
                Text("Recent Connections")
                    .font(.system(size: 11, weight: .bold, design: .rounded))

                if recentConnections.isEmpty {
                    Text("No connection data yet.")
                        .font(.system(size: 11, weight: .regular, design: .rounded))
                        .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            tableHeader("Time", width: 72)
                            tableHeader("Process", width: 152)
                            tableHeader("Proto", width: 52)
                            tableHeader("Location", width: 220)
                        }

                        ForEach(recentConnections) { connection in
                            HStack(spacing: 6) {
                                tableCell(Formatters.timestampString(connection.capturedAt), width: 72)
                                tableCell(connection.process, width: 152)
                                tableCell(connection.proto, width: 52)
                                tableCell(locationText(for: connection), width: 220)
                            }
                            .padding(.vertical, 3)
                            .padding(.horizontal, 4)
                            .background(connection.status == .suspicious ? AppTheme.danger.opacity(0.14) : AppTheme.surface.opacity(0.32))
                            .overlay(
                                RoundedRectangle(cornerRadius: 5, style: .continuous)
                                    .stroke(connection.status == .suspicious ? AppTheme.danger.opacity(0.7) : AppTheme.surfaceMuted.opacity(0.25), lineWidth: 1)
                            )
                        }
                    }
                }

                Divider()

                HStack(spacing: 8) {
                    Button("Refresh") {
                        viewModel.refreshNow()
                    }

                    Button(viewModel.isPaused ? "Resume" : "Pause") {
                        viewModel.togglePause()
                    }

                    Button("Open 10m History") {
                        openWindow(id: "history")
                        NSApplication.shared.activate(ignoringOtherApps: true)
                    }

                    Button("Open Full Application") {
                        viewModel.prepareToOpenMainWindow()
                        openWindow(id: "main")
                        NSApplication.shared.activate(ignoringOtherApps: true)
                    }

                    Spacer()

                    Button("Quit") {
                        NSApplication.shared.terminate(nil)
                    }
                }
            }
            .padding(12)
            .frame(width: 560)
        }
        .foregroundStyle(AppTheme.foreground)
    }

    private func locationText(for connection: NetworkConnection) -> String {
        if let location = connection.location?.trimmingCharacters(in: .whitespacesAndNewlines), !location.isEmpty {
            return location
        }

        let host = IPAddress.normalizedHost(connection.remote.host)
        if host.isEmpty || host == "*" {
            return "N/A"
        }

        if IPAddress.isPrivateOrLocal(host, localAddresses: []) {
            return connection.direction == .incoming ? "Local inbound" : "Local network"
        }

        if connection.direction == .incoming {
            return "Inbound from \(host)"
        }

        if connection.direction == .outgoing {
            if IPAddress.isIPAddress(host) {
                return "Resolving \(host)"
            }
            return host
        }

        return host
    }

    private func chip(_ title: String, _ value: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title)
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .foregroundStyle(AppTheme.selectionForeground.opacity(0.74))
            Text(value)
                .font(.system(size: 11, weight: .semibold, design: .rounded))
                .foregroundStyle(color)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(color.opacity(0.10))
        )
    }

    private func tableHeader(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 10, weight: .bold, design: .rounded))
            .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))
            .frame(width: width, alignment: .leading)
    }

    private func tableCell(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 10, weight: .regular, design: .monospaced))
            .lineLimit(1)
            .truncationMode(.tail)
            .frame(width: width, alignment: .leading)
    }
}
