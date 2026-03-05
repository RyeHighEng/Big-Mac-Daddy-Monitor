import SwiftUI
#if canImport(AppKit)
import AppKit
#endif

struct ContentView: View {
    @EnvironmentObject private var viewModel: MonitorViewModel
    @State private var selectedConnectionID: String?

    var body: some View {
        ZStack {
            AppTheme.background.ignoresSafeArea()

            VStack(spacing: 0) {
                SummaryBar()
                Divider()
                if !viewModel.diagnostics.isEmpty {
                    DiagnosticsBanner()
                    Divider()
                }
                TabView {
                    ConnectionsTab(selectedConnectionID: $selectedConnectionID)
                        .tabItem { Label("Traffic", systemImage: "network") }
                    PortsTab()
                        .tabItem { Label("Open Ports", systemImage: "cable.connector") }
                    SystemUsageTab()
                        .tabItem { Label("CPU/Memory", systemImage: "gauge.with.dots.needle.bottom.50percent") }
                    ProcessesTab()
                        .tabItem { Label("Processes", systemImage: "cpu") }
                    InterfacesTab()
                        .tabItem { Label("Interfaces", systemImage: "point.3.connected.trianglepath.dotted") }
                    RulesTab()
                        .tabItem { Label("Labels & Alerts", systemImage: "tag") }
                    DiagnosticsTab()
                        .tabItem { Label("Diagnostics", systemImage: "stethoscope") }
                }
            }
        }
        .foregroundStyle(AppTheme.foreground)
        .onAppear {
#if canImport(AppKit)
            if viewModel.shouldSuppressWindowOnAppear() {
                DispatchQueue.main.async {
                    // Hide only the auto-opened content window.
                    // Closing can terminate the app on some macOS setups.
                    if let contentWindow = NSApplication.shared.windows.first(where: { $0.isVisible && $0.contentViewController != nil }) {
                        contentWindow.orderOut(nil)
                    }
                }
            }
#endif
        }
    }
}

private struct DiagnosticsBanner: View {
    @EnvironmentObject private var viewModel: MonitorViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Monitoring warnings")
                .font(.system(size: 12, weight: .bold, design: .rounded))
                .foregroundStyle(AppTheme.warning)
            ForEach(viewModel.diagnostics, id: \.self) { message in
                Text("• \(message)")
                    .font(.system(size: 11, weight: .regular, design: .rounded))
                    .foregroundStyle(AppTheme.selectionForeground.opacity(0.8))
                    .lineLimit(2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(AppTheme.warning.opacity(0.16))
    }
}

private struct SummaryBar: View {
    @EnvironmentObject private var viewModel: MonitorViewModel

    var body: some View {
        HStack(spacing: 16) {
            SummaryChip(title: "Connections", value: "\(viewModel.connections.count)", tint: AppTheme.info)
            SummaryChip(title: "Suspicious", value: "\(viewModel.suspiciousCount)", tint: AppTheme.danger)
            SummaryChip(title: "Ignored", value: "\(viewModel.ignoredCount)", tint: AppTheme.surfaceMuted)
            SummaryChip(title: "Open Ports", value: "\(viewModel.ports.count)", tint: AppTheme.warning)
            SummaryChip(title: "CPU", value: Formatters.percentString(viewModel.summary.cpuPercent), tint: AppTheme.success)
            SummaryChip(
                title: "Net",
                value: Formatters.speedCompactString(
                    downloadBytesPerSecond: viewModel.summary.downloadBytesPerSecond,
                    uploadBytesPerSecond: viewModel.summary.uploadBytesPerSecond
                ),
                tint: AppTheme.info
            )
            SummaryChip(
                title: "Memory",
                value: "\(Formatters.bytesString(viewModel.summary.usedMemoryBytes)) / \(Formatters.bytesString(viewModel.summary.totalMemoryBytes))",
                tint: AppTheme.pink
            )

            Spacer()

            if let updated = viewModel.lastUpdated {
                Text("Updated \(Formatters.timestampString(updated))")
                    .font(.system(size: 12, weight: .medium, design: .rounded))
                    .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))
            }

            Button(action: viewModel.refreshNow) {
                Label(viewModel.isRefreshing ? "Refreshing" : "Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(viewModel.isRefreshing)

            Button(action: viewModel.togglePause) {
                Label(viewModel.isPaused ? "Resume" : "Pause", systemImage: viewModel.isPaused ? "play.fill" : "pause.fill")
            }
            .disabled(viewModel.isRefreshing)
        }
        .padding(12)
        .background(AppTheme.surface.opacity(0.92))
    }
}

private struct SummaryChip: View {
    let title: String
    let value: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.system(size: 11, weight: .semibold, design: .rounded))
                .foregroundStyle(AppTheme.selectionForeground.opacity(0.72))
            Text(value)
                .font(.system(size: 13, weight: .bold, design: .rounded))
                .foregroundStyle(tint)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(tint.opacity(0.10))
        )
    }
}

private struct ConnectionsTab: View {
    @EnvironmentObject private var viewModel: MonitorViewModel
    @Environment(\.openWindow) private var openWindow
    @Binding var selectedConnectionID: String?

    @State private var showIgnored = false
    @State private var searchText = ""

    private var filteredConnections: [NetworkConnection] {
        viewModel.connections.filter { connection in
            if !showIgnored && connection.status == .ignored { return false }
            if searchText.isEmpty { return true }
            let q = searchText.lowercased()
            return connection.process.lowercased().contains(q)
                || connection.local.displayText.lowercased().contains(q)
                || connection.remote.displayText.lowercased().contains(q)
                || connection.user.lowercased().contains(q)
        }
    }

    private var selectedConnection: NetworkConnection? {
        guard let selectedConnectionID else { return nil }
        return viewModel.connections.first(where: { $0.id == selectedConnectionID })
    }

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                TextField("Search process, IP, port, or user", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                Toggle("Show Ignored", isOn: $showIgnored)
                    .toggleStyle(.checkbox)
                Spacer()
                Text("Interval")
                    .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))
                Slider(value: $viewModel.refreshInterval, in: 1...10, step: 1)
                    .frame(width: 140)
                Text("\(Int(viewModel.refreshInterval))s")
                    .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))
                    .frame(width: 32)
                Button("Open 10m History") {
                    openWindow(id: "history")
                }
            }
            .padding(.horizontal)

            if let selectedConnection {
                HStack(spacing: 8) {
                    Text("Selected: \(selectedConnection.processDisplay) → \(selectedConnection.remote.displayText)")
                        .font(.system(size: 12, weight: .medium, design: .rounded))
                        .foregroundStyle(AppTheme.selectionForeground.opacity(0.8))
                    Spacer()
                    Button("Ignore Pattern") {
                        viewModel.addRule(from: selectedConnection, type: .ignore)
                    }
                    Button("Flag Suspicious") {
                        viewModel.addRule(from: selectedConnection, type: .suspicious)
                    }
                }
                .padding(.horizontal)
            }

            ScrollView([.horizontal, .vertical]) {
                if filteredConnections.isEmpty {
                    Text("No traffic rows available. Check Diagnostics tab for permission or collection issues.")
                        .font(.system(size: 13, weight: .medium, design: .rounded))
                        .foregroundStyle(AppTheme.selectionForeground.opacity(0.8))
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        ConnectionHeaderRow()
                        Divider()
                        ForEach(filteredConnections) { connection in
                            ConnectionDataRow(
                                connection: connection,
                                isSelected: selectedConnectionID == connection.id
                            )
                            .onTapGesture {
                                selectedConnectionID = connection.id
                            }
                        }
                    }
                    .padding(.horizontal)
                    .padding(.bottom)
                }
            }
        }
        .padding(.top, 12)
    }
}

private struct ConnectionHeaderRow: View {
    var body: some View {
        HStack(spacing: 8) {
            tableHeader("Time", width: 80)
            tableHeader("Direction", width: 92)
            tableHeader("Process", width: 190)
            tableHeader("User", width: 110)
            tableHeader("Proto", width: 56)
            tableHeader("Local", width: 210)
            tableHeader("Remote", width: 220)
            tableHeader("Location", width: 220)
            tableHeader("State", width: 120)
            tableHeader("Risk", width: 64)
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

private struct ConnectionDataRow: View {
    @EnvironmentObject private var viewModel: MonitorViewModel
    let connection: NetworkConnection
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 8) {
            cell(Formatters.timestampString(connection.capturedAt), width: 80)
            DirectionBadge(direction: connection.direction)
                .frame(width: 92, alignment: .leading)
            cell(connection.processDisplay, width: 190)
            cell(connection.user, width: 110)
            cell(connection.proto, width: 56)
            cell(connection.local.displayText, width: 210)
            cell(connection.remote.displayText, width: 220)
            cell(connection.location ?? "-", width: 220)
            cell(connection.state, width: 120)
            riskCell(width: 64)
            StatusBadge(status: connection.status)
                .frame(width: 100, alignment: .leading)
        }
        .font(.system(size: 12, weight: .regular, design: .monospaced))
        .padding(.vertical, 5)
        .padding(.horizontal, 6)
        .background(backgroundColor)
        .overlay(
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .stroke(borderColor, lineWidth: borderWidth)
        )
    }

    private var backgroundColor: Color {
        if isSelected { return AppTheme.cursor.opacity(0.18) }
        switch connection.status {
        case .ignored:
            return AppTheme.surfaceMuted.opacity(0.16)
        case .suspicious:
            return AppTheme.danger.opacity(0.16)
        case .normal:
            return .clear
        }
    }

    private var borderColor: Color {
        if connection.status == .suspicious { return AppTheme.danger }
        if isSelected { return AppTheme.cursor }
        return .clear
    }

    private var borderWidth: CGFloat {
        connection.status == .suspicious || isSelected ? 1.2 : 0
    }

    private func cell(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .lineLimit(1)
            .truncationMode(.tail)
            .foregroundStyle(connection.status == .ignored ? AppTheme.selectionForeground.opacity(0.65) : AppTheme.foreground)
            .frame(width: width, alignment: .leading)
    }

    private func riskCell(width: CGFloat) -> some View {
        let score = viewModel.riskScore(for: connection)
        let reasons = viewModel.riskReasons(for: connection)
        return Text("\(score)")
            .lineLimit(1)
            .foregroundStyle(riskColor(score))
            .help(reasons.isEmpty ? "No high-confidence signals yet." : reasons.joined(separator: " | "))
            .frame(width: width, alignment: .leading)
    }

    private func riskColor(_ score: Int) -> Color {
        if score >= 70 { return AppTheme.danger }
        if score >= 40 { return AppTheme.warning }
        return AppTheme.success
    }
}

private struct DirectionBadge: View {
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

private struct StatusBadge: View {
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

private struct PortsTab: View {
    @EnvironmentObject private var viewModel: MonitorViewModel

    var body: some View {
        ScrollView([.horizontal, .vertical]) {
            if viewModel.ports.isEmpty {
                Text("No open-port rows available. Check Diagnostics tab if this looks wrong.")
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(AppTheme.selectionForeground.opacity(0.8))
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        header("Proto", width: 56)
                        header("Port", width: 80)
                        header("Endpoint", width: 220)
                        header("Process", width: 220)
                        header("User", width: 130)
                        header("State", width: 120)
                    }
                    Divider()
                    ForEach(viewModel.ports) { port in
                        HStack(spacing: 8) {
                            cell(port.proto, width: 56)
                            cell("\(port.endpoint.port ?? 0)", width: 80)
                            cell(port.endpoint.displayText, width: 220)
                            cell(port.processDisplay, width: 220)
                            cell(port.user, width: 130)
                            cell(port.state, width: 120)
                        }
                        .padding(.vertical, 5)
                        .padding(.horizontal, 6)
                        .background(AppTheme.warning.opacity(0.10))
                        .overlay(
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .stroke(AppTheme.warning.opacity(0.28), lineWidth: 1)
                        )
                    }
                }
                .padding()
            }
        }
    }

    private func header(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 11, weight: .bold, design: .rounded))
            .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))
            .frame(width: width, alignment: .leading)
    }

    private func cell(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 12, weight: .regular, design: .monospaced))
            .lineLimit(1)
            .frame(width: width, alignment: .leading)
    }
}

private struct SystemUsageTab: View {
    @EnvironmentObject private var viewModel: MonitorViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            GroupBox("System Load") {
                VStack(alignment: .leading, spacing: 10) {
                    metric("CPU Usage", value: Formatters.percentString(viewModel.summary.cpuPercent), tint: AppTheme.success)
                    metric(
                        "Memory Used",
                        value: "\(Formatters.bytesString(viewModel.summary.usedMemoryBytes)) of \(Formatters.bytesString(viewModel.summary.totalMemoryBytes))",
                        tint: AppTheme.pink
                    )
                    metric("Memory Free", value: Formatters.bytesString(viewModel.summary.freeMemoryBytes), tint: AppTheme.info)
                    metric(
                        "Network Speed",
                        value: "Down \(Formatters.speedString(bytesPerSecond: viewModel.summary.downloadBytesPerSecond)) | Up \(Formatters.speedString(bytesPerSecond: viewModel.summary.uploadBytesPerSecond))",
                        tint: AppTheme.info
                    )
                    metric("GPU Usage", value: "Unavailable (requires privileged sampler)", tint: AppTheme.selectionForeground.opacity(0.7))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("Top CPU Processes") {
                tableForProcesses(viewModel.topCPUProcesses.prefix(15).map { $0 })
            }

            Spacer()
        }
        .padding()
    }

    private func metric(_ title: String, value: String, tint: Color) -> some View {
        HStack {
            Text(title)
                .font(.system(size: 13, weight: .semibold, design: .rounded))
            Spacer()
            Text(value)
                .font(.system(size: 13, weight: .bold, design: .rounded))
                .foregroundStyle(tint)
        }
    }

    private func tableForProcesses(_ processes: [ProcessUsage]) -> some View {
        VStack(spacing: 4) {
            HStack {
                Text("PID").frame(width: 80, alignment: .leading)
                Text("Process").frame(width: 260, alignment: .leading)
                Text("CPU").frame(width: 90, alignment: .leading)
                Text("Memory").frame(width: 140, alignment: .leading)
                Spacer()
            }
            .font(.system(size: 11, weight: .bold, design: .rounded))
            .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))

            ForEach(processes) { process in
                HStack {
                    monoText("\(process.pid)", width: 80)
                    monoText(process.processName, width: 260)
                    monoText(Formatters.percentString(process.cpuPercent), width: 90)
                    monoText(Formatters.bytesString(process.memoryBytes), width: 140)
                    Spacer()
                }
                .padding(.vertical, 4)
                .padding(.horizontal, 6)
                .background(AppTheme.info.opacity(0.10))
                .overlay(
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .stroke(AppTheme.info.opacity(0.26), lineWidth: 1)
                )
            }
        }
    }

    private func monoText(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 12, weight: .regular, design: .monospaced))
            .lineLimit(1)
            .truncationMode(.tail)
            .frame(width: width, alignment: .leading)
    }
}

private struct ProcessesTab: View {
    @EnvironmentObject private var viewModel: MonitorViewModel
    @State private var mode: ProcessSortMode = .cpu

    var body: some View {
        VStack(spacing: 10) {
            Picker("Sort", selection: $mode) {
                ForEach(ProcessSortMode.allCases, id: \.self) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)

            ScrollView([.vertical, .horizontal]) {
                if displayedProcesses.isEmpty {
                    Text("No process rows available. Check Diagnostics tab for permission details.")
                        .font(.system(size: 13, weight: .medium, design: .rounded))
                        .foregroundStyle(AppTheme.selectionForeground.opacity(0.8))
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            header("PID", width: 70)
                            header("Process", width: 200)
                            header("CPU", width: 80)
                            header("Memory", width: 120)
                            header("Path", width: 600)
                        }
                        Divider()

                        ForEach(displayedProcesses) { process in
                            HStack(spacing: 8) {
                                cell("\(process.pid)", width: 70)
                                cell(process.processName, width: 200)
                                cell(Formatters.percentString(process.cpuPercent), width: 80)
                                cell(Formatters.bytesString(process.memoryBytes), width: 120)
                                cell(process.path ?? "-", width: 600)
                            }
                            .padding(.vertical, 4)
                            .padding(.horizontal, 6)
                            .background(AppTheme.pink.opacity(0.10))
                            .overlay(
                                RoundedRectangle(cornerRadius: 7, style: .continuous)
                                    .stroke(AppTheme.pink.opacity(0.28), lineWidth: 1)
                            )
                        }
                    }
                    .padding()
                }
            }
        }
        .padding(.top, 12)
    }

    private var displayedProcesses: [ProcessUsage] {
        switch mode {
        case .cpu:
            return viewModel.topCPUProcesses
        case .memory:
            return viewModel.topMemoryProcesses
        }
    }

    private func header(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 11, weight: .bold, design: .rounded))
            .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))
            .frame(width: width, alignment: .leading)
    }

    private func cell(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 12, weight: .regular, design: .monospaced))
            .lineLimit(1)
            .truncationMode(.tail)
            .frame(width: width, alignment: .leading)
    }
}

private enum ProcessSortMode: String, CaseIterable {
    case cpu = "Top CPU"
    case memory = "Top Memory"
}

private struct InterfacesTab: View {
    @EnvironmentObject private var viewModel: MonitorViewModel

    var body: some View {
        ScrollView([.horizontal, .vertical]) {
            if viewModel.interfaces.isEmpty {
                Text("No interface rows available.")
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(AppTheme.selectionForeground.opacity(0.8))
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        header("Name", width: 120)
                        header("Family", width: 80)
                        header("Address", width: 220)
                        header("Netmask", width: 220)
                        header("Up", width: 60)
                        header("Loopback", width: 80)
                    }
                    Divider()

                    ForEach(viewModel.interfaces) { item in
                        HStack(spacing: 8) {
                            cell(item.name, width: 120)
                            cell(item.family, width: 80)
                            cell(item.address, width: 220)
                            cell(item.netmask ?? "-", width: 220)
                            cell(item.isUp ? "Yes" : "No", width: 60)
                            cell(item.isLoopback ? "Yes" : "No", width: 80)
                        }
                        .padding(.vertical, 4)
                        .padding(.horizontal, 6)
                        .background(AppTheme.info.opacity(0.10))
                        .overlay(
                            RoundedRectangle(cornerRadius: 7, style: .continuous)
                                .stroke(AppTheme.info.opacity(0.26), lineWidth: 1)
                        )
                    }
                }
                .padding()
            }
        }
    }

    private func header(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 11, weight: .bold, design: .rounded))
            .foregroundStyle(AppTheme.selectionForeground.opacity(0.75))
            .frame(width: width, alignment: .leading)
    }

    private func cell(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 12, weight: .regular, design: .monospaced))
            .lineLimit(1)
            .truncationMode(.tail)
            .frame(width: width, alignment: .leading)
    }
}

private struct RulesTab: View {
    @EnvironmentObject private var viewModel: MonitorViewModel

    @State private var selectedType: RuleType = .ignore
    @State private var processContains = ""
    @State private var hostContains = ""
    @State private var remotePort = ""
    @State private var note = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            GroupBox("Add Rule") {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("Type", selection: $selectedType) {
                        ForEach(RuleType.allCases, id: \.self) { type in
                            Text(type.rawValue).tag(type)
                        }
                    }
                    .pickerStyle(.segmented)

                    HStack {
                        TextField("Process contains", text: $processContains)
                        TextField("Remote host contains", text: $hostContains)
                        TextField("Remote port", text: $remotePort)
                            .frame(width: 110)
                    }

                    TextField("Note", text: $note)

                    HStack {
                        Button("Add Rule") {
                            addRule()
                        }
                        .disabled(processContains.isEmpty && hostContains.isEmpty && remotePort.isEmpty)

                        Button("Clear All Rules", role: .destructive) {
                            viewModel.clearRules()
                        }

                        Spacer()
                    }
                }
            }

            GroupBox("Current Rules") {
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(viewModel.rules) { rule in
                            HStack(spacing: 8) {
                                Text(rule.type.rawValue)
                                    .font(.system(size: 11, weight: .bold, design: .rounded))
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 3)
                                    .background(
                                        Capsule(style: .continuous)
                                            .fill((rule.type == .ignore ? AppTheme.surfaceMuted : AppTheme.danger).opacity(0.24))
                                    )
                                Text("proc=\(rule.processContains.isEmpty ? "*" : rule.processContains)")
                                Text("host=\(rule.remoteHostContains.isEmpty ? "*" : rule.remoteHostContains)")
                                Text("port=\(rule.remotePort.map(String.init) ?? "*")")
                                Text("note=\(rule.note)")
                                    .foregroundStyle(AppTheme.selectionForeground.opacity(0.8))
                                    .lineLimit(1)
                                Spacer()
                                Button("Delete", role: .destructive) {
                                    viewModel.removeRule(rule)
                                }
                            }
                            .font(.system(size: 12, weight: .regular, design: .monospaced))
                            .padding(.vertical, 5)
                            .padding(.horizontal, 6)
                            .background(AppTheme.surfaceMuted.opacity(0.14))
                            .overlay(
                                RoundedRectangle(cornerRadius: 7, style: .continuous)
                                    .stroke(AppTheme.surfaceMuted.opacity(0.34), lineWidth: 1)
                            )
                        }
                    }
                }
            }

            Spacer()
        }
        .padding()
    }

    private func addRule() {
        let parsedPort = Int(remotePort.trimmingCharacters(in: .whitespacesAndNewlines))
        let rule = TrafficRule(
            type: selectedType,
            processContains: processContains.trimmingCharacters(in: .whitespacesAndNewlines),
            remoteHostContains: hostContains.trimmingCharacters(in: .whitespacesAndNewlines),
            remotePort: parsedPort,
            note: note.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Manual rule" : note
        )
        viewModel.rules.insert(rule, at: 0)
        viewModel.saveRuleChanges()

        processContains = ""
        hostContains = ""
        remotePort = ""
        note = ""
    }
}

private struct DiagnosticsTab: View {
    @EnvironmentObject private var viewModel: MonitorViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                GroupBox("Collector Health") {
                    VStack(alignment: .leading, spacing: 8) {
                        if viewModel.diagnostics.isEmpty {
                            Text("No current warnings. Collectors are running normally.")
                                .font(.system(size: 13, weight: .medium, design: .rounded))
                                .foregroundStyle(AppTheme.success)
                        } else {
                            ForEach(viewModel.diagnostics, id: \.self) { message in
                                Text("• \(message)")
                                    .font(.system(size: 12, weight: .regular, design: .rounded))
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                GroupBox("Permission Checklist") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("1. Run from Terminal: `swift run`.")
                        Text("2. Add ThreatFox key in `.env` as `THREATFOX_API_KEY=...` to enable IOC auto-flagging.")
                        Text("3. If process data is empty, grant Terminal Full Disk Access in System Settings > Privacy & Security.")
                        Text("4. If traffic looks empty, ensure no endpoint protection is blocking `lsof`.")
                        Text("5. Use Refresh after changing permissions.")
                    }
                    .font(.system(size: 12, weight: .regular, design: .rounded))
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                Spacer()
            }
            .padding()
        }
    }
}
