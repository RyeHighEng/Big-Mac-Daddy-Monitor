import Foundation
import Combine

@MainActor
final class MonitorViewModel: ObservableObject {
    @Published var connections: [NetworkConnection] = []
    @Published var historyConnections: [HistoricalConnection] = []
    @Published var ports: [PortRecord] = []
    @Published var summary = SystemSummary(
        cpuPercent: 0,
        usedMemoryBytes: 0,
        freeMemoryBytes: 0,
        totalMemoryBytes: ProcessInfo.processInfo.physicalMemory,
        downloadBytesPerSecond: 0,
        uploadBytesPerSecond: 0
    )
    @Published var processes: [ProcessUsage] = []
    @Published var interfaces: [InterfaceRecord] = []
    @Published var rules: [TrafficRule] = []
    @Published var diagnostics: [String] = []
    @Published var allowMainWindowPresentation = false

    @Published var isRefreshing = false
    @Published var isPaused = false
    @Published var lastUpdated: Date?
    @Published var refreshInterval: Double = 3

    private let collector = MonitorCollector()
    private let geoService = GeoIPService()
    private let threatIntelService = ThreatIntelService()
    private let rulesStore = RulesStore()
    private var pollingTask: Task<Void, Never>?
    private var geoEnrichmentTask: Task<Void, Never>?
    private var threatIntelTask: Task<Void, Never>?
    private var threatIntelByConnectionID: [String: ThreatFoxVerdict] = [:]
    private var threatIntelWarningShown = false

    private let suspiciousPorts: Set<Int> = [4444, 5555, 6666, 1337, 31337]
    private let historyWindowSeconds: TimeInterval = 600
    private let historyHardLimit = 25_000

    init() {
        self.rules = rulesStore.load()
        startPolling()
    }

    func startPolling() {
        pollingTask?.cancel()
        pollingTask = Task {
            while !Task.isCancelled {
                if isPaused {
                    try? await Task.sleep(nanoseconds: 300_000_000)
                    continue
                }
                await refresh()
                let interval = UInt64(max(1, refreshInterval) * 1_000_000_000)
                try? await Task.sleep(nanoseconds: interval)
            }
        }
    }

    func refreshNow() {
        Task {
            await refresh()
        }
    }

    func togglePause() {
        isPaused.toggle()
    }

    func clearHistory() {
        historyConnections = []
    }

    func prepareToOpenMainWindow() {
        allowMainWindowPresentation = true
    }

    func shouldSuppressWindowOnAppear() -> Bool {
        if allowMainWindowPresentation {
            allowMainWindowPresentation = false
            return false
        }
        return true
    }

    func saveRuleChanges() {
        rulesStore.save(rules)
        reapplyRuleStatus()
    }

    func addRule(from connection: NetworkConnection, type: RuleType) {
        let rule = TrafficRule(
            type: type,
            processContains: connection.process,
            remoteHostContains: connection.remote.host,
            remotePort: connection.remote.port,
            note: type == .ignore ? "Trusted pattern" : "Manually flagged"
        )
        rules.insert(rule, at: 0)
        saveRuleChanges()
    }

    func removeRule(_ rule: TrafficRule) {
        rules.removeAll { $0.id == rule.id }
        saveRuleChanges()
    }

    func clearRules() {
        rules = []
        saveRuleChanges()
    }

    var topCPUProcesses: [ProcessUsage] {
        processes.topByCPU(limit: 40)
    }

    var topMemoryProcesses: [ProcessUsage] {
        processes.topByMemory(limit: 40)
    }

    var suspiciousCount: Int {
        connections.filter { $0.status == .suspicious }.count
    }

    var ignoredCount: Int {
        connections.filter { $0.status == .ignored }.count
    }

    private func refresh() async {
        if isPaused { return }
        isRefreshing = true

        let snapshot = await collector.collectSnapshot()
        var updatedConnections = snapshot.connections
        let activeIDs = Set(updatedConnections.map(\.id))
        threatIntelByConnectionID = threatIntelByConnectionID.filter { activeIDs.contains($0.key) }
        applyStatus(to: &updatedConnections)
        appendHistory(from: updatedConnections)

        connections = updatedConnections
        ports = snapshot.ports
        summary = snapshot.summary
        processes = snapshot.processes
        interfaces = snapshot.interfaces
        diagnostics = snapshot.warnings
        lastUpdated = Date()
        isRefreshing = false

        if SecretsResolver.threatFoxAPIKey() == nil {
            diagnostics.append("Threat intel is disabled: missing THREATFOX_API_KEY in .env or environment.")
        }

        let cpuText = String(format: "%.1f", summary.cpuPercent)
        print(
            "[MacMonitor] connections=\(connections.count) ports=\(ports.count) processes=\(processes.count) cpu=\(cpuText) down=\(summary.downloadBytesPerSecond)B/s up=\(summary.uploadBytesPerSecond)B/s warnings=\(diagnostics.count)"
        )

        geoEnrichmentTask?.cancel()
        geoEnrichmentTask = Task { [weak self] in
            guard let self else { return }
            await self.enrichGeoIPIfNeeded()
        }

        threatIntelTask?.cancel()
        threatIntelTask = Task { [weak self] in
            guard let self else { return }
            await self.enrichThreatIntelIfNeeded()
        }
    }

    private func applyStatus(to connections: inout [NetworkConnection]) {
        for index in connections.indices {
            connections[index].status = status(for: connections[index])
        }
    }

    private func reapplyRuleStatus() {
        var updated = connections
        applyStatus(to: &updated)
        connections = updated
    }

    private func status(for connection: NetworkConnection) -> TrafficStatus {
        if rules.contains(where: { $0.type == .ignore && $0.matches(connection) }) {
            return .ignored
        }
        if rules.contains(where: { $0.type == .suspicious && $0.matches(connection) }) {
            return .suspicious
        }
        if let remotePort = connection.remote.port,
           suspiciousPorts.contains(remotePort),
           connection.direction == .outgoing {
            return .suspicious
        }
        if let intel = threatIntelByConnectionID[connection.id], intel.malicious {
            return .suspicious
        }
        if riskScore(for: connection) >= 70 {
            return .suspicious
        }
        return .normal
    }

    private func enrichGeoIPIfNeeded() async {
        let targets = connections
            .filter { $0.direction == .outgoing && $0.location == nil }
            .compactMap { connection -> (String, String)? in
                let host = IPAddress.normalizedHost(connection.remote.host)
                guard IPAddress.isIPAddress(host) else { return nil }
                guard !IPAddress.isPrivateOrLocal(host, localAddresses: []) else { return nil }
                return (connection.id, host)
            }

        guard !targets.isEmpty else { return }

        for (connectionID, ip) in targets {
            if Task.isCancelled { return }
            guard let location = await geoService.lookup(ip: ip) else { continue }
            if let idx = connections.firstIndex(where: { $0.id == connectionID }) {
                connections[idx].location = location
            }
            updateHistoryLocation(connectionID: connectionID, location: location)
        }
    }

    private func appendHistory(from connections: [NetworkConnection]) {
        let now = Date()
        let newEntries = connections.enumerated().map { offset, connection in
            HistoricalConnection(
                id: "\(connection.id)-\(Int(now.timeIntervalSince1970 * 1000))-\(offset)",
                capturedAt: connection.capturedAt,
                connection: connection
            )
        }

        historyConnections.insert(contentsOf: newEntries, at: 0)
        pruneHistory(now: now)
    }

    private func pruneHistory(now: Date) {
        let cutoff = now.addingTimeInterval(-historyWindowSeconds)
        historyConnections.removeAll { $0.capturedAt < cutoff }
        if historyConnections.count > historyHardLimit {
            historyConnections = Array(historyConnections.prefix(historyHardLimit))
        }
    }

    private func updateHistoryLocation(connectionID: String, location: String) {
        for index in historyConnections.indices where historyConnections[index].connection.id == connectionID {
            historyConnections[index].connection.location = location
        }
    }

    func riskScore(for connection: NetworkConnection) -> Int {
        riskAssessment(for: connection).score
    }

    func riskReasons(for connection: NetworkConnection) -> [String] {
        riskAssessment(for: connection).reasons
    }

    private func riskAssessment(for connection: NetworkConnection) -> ThreatIntelAssessment {
        var score = 0
        var reasons: [String] = []
        var source: String?
        var matchedIndicator: String?

        if connection.direction == .outgoing {
            score += 12
            reasons.append("Outbound traffic")
        }

        let host = IPAddress.normalizedHost(connection.remote.host)
        if IPAddress.isIPAddress(host), !IPAddress.isPrivateOrLocal(host, localAddresses: []) {
            score += 8
            reasons.append("Public IP destination")
        }

        if let remotePort = connection.remote.port, suspiciousPorts.contains(remotePort) {
            score += 28
            reasons.append("High-risk destination port \(remotePort)")
        }

        if let intel = threatIntelByConnectionID[connection.id], intel.malicious {
            score += max(65, intel.confidence)
            reasons.append("Threat intel match: \(intel.reason)")
            source = intel.source
            matchedIndicator = intel.matchedIndicator
        }

        if connection.direction == .outgoing, connection.location == nil, IPAddress.isIPAddress(host) {
            score += 6
            reasons.append("GeoIP unresolved")
        }

        let normalizedScore = max(0, min(score, 100))
        return ThreatIntelAssessment(
            score: normalizedScore,
            autoSuspicious: normalizedScore >= 70,
            reasons: reasons,
            source: source,
            matchedIndicator: matchedIndicator
        )
    }

    private func enrichThreatIntelIfNeeded() async {
        guard SecretsResolver.threatFoxAPIKey() != nil else {
            if !threatIntelWarningShown {
                threatIntelWarningShown = true
            }
            return
        }

        let targets = connections
            .filter { $0.direction == .outgoing }
            .compactMap { connection -> (String, String)? in
                let host = IPAddress.normalizedHost(connection.remote.host)
                guard !host.isEmpty, host != "*", !IPAddress.isPrivateOrLocal(host, localAddresses: []) else { return nil }
                return (connection.id, host)
            }

        guard !targets.isEmpty else { return }

        var seenHosts = Set<String>()
        let uniqueTargets = targets.filter { entry in
            if seenHosts.contains(entry.1) { return false }
            seenHosts.insert(entry.1)
            return true
        }.prefix(20)

        for (connectionID, host) in uniqueTargets {
            if Task.isCancelled { return }
            guard let verdict = await threatIntelService.lookupIndicator(host) else { continue }
            threatIntelByConnectionID[connectionID] = verdict
            if verdict.malicious {
                let message = "Threat intel hit (\(verdict.source)): \(host) -> \(verdict.reason)"
                if !diagnostics.contains(message) {
                    diagnostics.append(message)
                }
            }
            reapplyRuleStatus()
        }
    }
}
