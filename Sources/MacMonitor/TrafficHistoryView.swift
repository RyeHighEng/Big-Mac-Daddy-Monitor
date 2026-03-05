import SwiftUI

struct TrafficHistoryView: View {
    @EnvironmentObject private var viewModel: MonitorViewModel
    @State private var searchText = ""
    @State private var showIgnored = true

    private var filteredHistory: [HistoricalConnection] {
        viewModel.historyConnections.filter { item in
            if !showIgnored && item.connection.status == .ignored { return false }
            if searchText.isEmpty { return true }
            let q = searchText.lowercased()
            let connection = item.connection
            return connection.process.lowercased().contains(q)
                || connection.local.displayText.lowercased().contains(q)
                || connection.remote.displayText.lowercased().contains(q)
                || connection.user.lowercased().contains(q)
                || (connection.location?.lowercased().contains(q) ?? false)
        }
    }

    var body: some View {
        ZStack {
            AppTheme.background.ignoresSafeArea()

            VStack(spacing: 10) {
                HStack(spacing: 10) {
                    Text("Traffic History (Last 10 Minutes)")
                        .font(.system(size: 15, weight: .bold, design: .rounded))
                    Spacer()
                    Toggle("Show Ignored", isOn: $showIgnored)
                        .toggleStyle(.checkbox)
                    TextField("Search process, IP, port, user, location", text: $searchText)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 320)
                    Button("Clear") {
                        viewModel.clearHistory()
                    }
                }
                .padding(.horizontal)
                .padding(.top, 10)

                ScrollView([.horizontal, .vertical]) {
                    if filteredHistory.isEmpty {
                        Text("No historical traffic rows captured yet.")
                            .font(.system(size: 13, weight: .medium, design: .rounded))
                            .foregroundStyle(AppTheme.selectionForeground.opacity(0.8))
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        VStack(alignment: .leading, spacing: 4) {
                            HistoryHeaderRow()
                            Divider()
                            ForEach(filteredHistory) { item in
                                HistoryDataRow(item: item)
                            }
                        }
                        .padding(.horizontal)
                        .padding(.bottom)
                    }
                }
            }
        }
        .foregroundStyle(AppTheme.foreground)
    }
}

private struct HistoryHeaderRow: View {
    var body: some View {
        HStack(spacing: 8) {
            tableHeader("Captured", width: 80)
            tableHeader("Direction", width: 92)
            tableHeader("Process", width: 190)
            tableHeader("User", width: 110)
            tableHeader("Proto", width: 56)
            tableHeader("Local", width: 210)
            tableHeader("Remote", width: 220)
            tableHeader("Location", width: 220)
            tableHeader("State", width: 120)
            tableHeader("Status", width: 100)
        }
        .font(.system(size: 11, weight: .bold, design: .rounded))
    }

    private func tableHeader(_ label: String, width: CGFloat) -> some View {
        Text(label)
            .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))
            .frame(width: width, alignment: .leading)
    }
}

private struct HistoryDataRow: View {
    let item: HistoricalConnection

    var body: some View {
        HStack(spacing: 8) {
            cell(Formatters.timestampString(item.capturedAt), width: 80)
            HistoryDirectionBadge(direction: item.connection.direction)
                .frame(width: 92, alignment: .leading)
            cell(item.connection.processDisplay, width: 190)
            cell(item.connection.user, width: 110)
            cell(item.connection.proto, width: 56)
            cell(item.connection.local.displayText, width: 210)
            cell(item.connection.remote.displayText, width: 220)
            cell(locationText, width: 220)
            cell(item.connection.state, width: 120)
            HistoryStatusBadge(status: item.connection.status)
                .frame(width: 100, alignment: .leading)
        }
        .font(.system(size: 12, weight: .regular, design: .monospaced))
        .padding(.vertical, 5)
        .padding(.horizontal, 6)
        .background(backgroundColor)
        .overlay(
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .stroke(borderColor, lineWidth: 1)
        )
    }

    private var backgroundColor: Color {
        switch item.connection.status {
        case .ignored:
            return AppTheme.surfaceMuted.opacity(0.16)
        case .suspicious:
            return AppTheme.danger.opacity(0.16)
        case .normal:
            return .clear
        }
    }

    private var borderColor: Color {
        item.connection.status == .suspicious ? AppTheme.danger : .clear
    }

    private var locationText: String {
        if let location = item.connection.location?.trimmingCharacters(in: .whitespacesAndNewlines), !location.isEmpty {
            return location
        }

        let host = IPAddress.normalizedHost(item.connection.remote.host)
        if host.isEmpty || host == "*" {
            return "N/A"
        }

        if IPAddress.isPrivateOrLocal(host, localAddresses: []) {
            return item.connection.direction == .incoming ? "Local inbound" : "Local network"
        }

        if item.connection.direction == .incoming {
            return "Inbound from \(host)"
        }

        if item.connection.direction == .outgoing {
            if IPAddress.isIPAddress(host) {
                return "Resolving \(host)"
            }
            return host
        }

        return host
    }

    private func cell(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .lineLimit(1)
            .truncationMode(.tail)
            .foregroundStyle(item.connection.status == .ignored ? AppTheme.selectionForeground.opacity(0.65) : AppTheme.foreground)
            .frame(width: width, alignment: .leading)
    }
}

private struct HistoryDirectionBadge: View {
    let direction: TrafficDirection

    var body: some View {
        Text(direction.rawValue)
            .font(.system(size: 11, weight: .semibold, design: .rounded))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(
                Capsule(style: .continuous)
                    .fill(color.opacity(0.18))
            )
            .foregroundStyle(color)
    }

    private var color: Color {
        switch direction {
        case .outgoing: return AppTheme.info
        case .incoming: return AppTheme.warning
        case .local: return AppTheme.surfaceMuted
        case .unknown: return AppTheme.pink
        }
    }
}

private struct HistoryStatusBadge: View {
    let status: TrafficStatus

    var body: some View {
        Text(status.rawValue)
            .font(.system(size: 11, weight: .semibold, design: .rounded))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(
                Capsule(style: .continuous)
                    .fill(color.opacity(0.2))
            )
            .foregroundStyle(color)
    }

    private var color: Color {
        switch status {
        case .normal: return AppTheme.success
        case .ignored: return AppTheme.surfaceMuted
        case .suspicious: return AppTheme.danger
        }
    }
}
