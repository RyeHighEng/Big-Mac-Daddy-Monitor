import Foundation
import Combine

@MainActor
final class MonitorViewModel: ObservableObject {
    private struct HostVerdictCacheEntry {
        let verdict: ThreatFoxVerdict
        let updatedAt: Date
    }

    @Published var connections: [NetworkConnection] = []
    @Published var historyConnections: [HistoricalConnection] = []
    @Published var frozenHistoryConnections: [HistoricalConnection] = []
    @Published var frozenHistoryCapturedAt: Date?
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
    // UI snapshot publish interval in seconds.
    @Published var refreshInterval: Double = 5

    private let collector = MonitorCollector()
    private let geoService = GeoIPService()
    private let threatIntelService = ThreatIntelService()
    private let rulesStore = RulesStore()
    private var pollingTask: Task<Void, Never>?
    private var geoEnrichmentTask: Task<Void, Never>?
    private var threatIntelTask: Task<Void, Never>?
    private var threatIntelByHost: [String: HostVerdictCacheEntry] = [:]
    private var riskAssessmentCache: [String: ThreatIntelAssessment] = [:]
    private var threatIntelWarningShown = false
    private var isCollectingSnapshot = false
    private var stagedSnapshot: StagedSnapshot?
    private var lastPublishedAt = Date.distantPast
    private var forcePublishRequested = false

    private let suspiciousPorts: Set<Int> = [4444, 5555, 6666, 1337, 31337]
    private let historyWindowSeconds: TimeInterval = 600
    private let historyHardLimit = 15_000
    private let historyDedupWindowSeconds: TimeInterval = 5
    private var lastHistoryEventByConnectionID: [String: Date] = [:]
    private let threatVerdictTTL: TimeInterval = 1800
    private let backgroundPollInterval: TimeInterval = 2

    private struct StagedSnapshot {
        let connections: [NetworkConnection]
        let ports: [PortRecord]
        let summary: SystemSummary
        let processes: [ProcessUsage]
        let interfaces: [InterfaceRecord]
        let warnings: [String]
    }

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
                await collectAndStageSnapshot()
                publishStagedSnapshotIfNeeded()
                let interval = UInt64(max(1, backgroundPollInterval) * 1_000_000_000)
                try? await Task.sleep(nanoseconds: interval)
            }
        }
    }

    func refreshNow() {
        Task {
            isRefreshing = true
            forcePublishRequested = true
            await collectAndStageSnapshot()
            publishStagedSnapshotIfNeeded(force: true)
            isRefreshing = false
        }
    }

    func togglePause() {
        isPaused.toggle()
    }

    func clearHistory() {
        historyConnections = []
        frozenHistoryConnections = []
        frozenHistoryCapturedAt = nil
        lastHistoryEventByConnectionID = [:]
    }

    func freezeHistorySnapshot() {
        // Freeze newest-first view so the history window does not mutate while inspecting.
        frozenHistoryConnections = Array(historyConnections.reversed())
        frozenHistoryCapturedAt = Date()
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

    private func collectAndStageSnapshot() async {
        if isPaused || isCollectingSnapshot { return }
        isCollectingSnapshot = true
        defer { isCollectingSnapshot = false }

        let snapshot = await collector.collectSnapshot()
        var updatedConnections = snapshot.connections
        pruneThreatVerdicts(now: Date(), activeConnections: updatedConnections)
        riskAssessmentCache.removeAll(keepingCapacity: true)
        applyStatus(to: &updatedConnections)
        appendHistory(from: updatedConnections)

        stagedSnapshot = StagedSnapshot(
            connections: updatedConnections,
            ports: snapshot.ports,
            summary: snapshot.summary,
            processes: snapshot.processes,
            interfaces: snapshot.interfaces,
            warnings: snapshot.warnings
        )
    }

    private func publishStagedSnapshotIfNeeded(force: Bool = false) {
        guard let stagedSnapshot else { return }
        let now = Date()
        let publishInterval = max(1, refreshInterval)
        if !force && !forcePublishRequested && now.timeIntervalSince(lastPublishedAt) < publishInterval {
            return
        }

        connections = stagedSnapshot.connections
        ports = stagedSnapshot.ports
        summary = stagedSnapshot.summary
        processes = stagedSnapshot.processes
        interfaces = stagedSnapshot.interfaces
        diagnostics = stagedSnapshot.warnings
        lastUpdated = now
        lastPublishedAt = now
        forcePublishRequested = false

        if SecretsResolver.threatFoxAPIKey() == nil {
            diagnostics.append("Threat intel is disabled: missing THREATFOX_API_KEY in .env or environment.")
        }

        let cpuText = String(format: "%.1f", summary.cpuPercent)
        print(
            "[MacMonitor] connections=\(connections.count) ports=\(ports.count) processes=\(processes.count) cpu=\(cpuText) down=\(summary.downloadBytesPerSecond)B/s up=\(summary.uploadBytesPerSecond)B/s warnings=\(diagnostics.count)"
        )

        startGeoEnrichmentIfIdle()
        startThreatIntelIfIdle()
    }

    private func applyStatus(to connections: inout [NetworkConnection]) {
        for index in connections.indices {
            connections[index].status = status(for: connections[index])
        }
    }

    private func reapplyRuleStatus() {
        riskAssessmentCache.removeAll(keepingCapacity: true)
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
        if let intel = threatVerdict(for: connection), intel.malicious {
            return .suspicious
        }
        if lightweightRiskScore(for: connection) >= 70 {
            return .suspicious
        }
        return .normal
    }

    private func enrichGeoIPIfNeeded() async {
        let unresolved = connections
            .filter { $0.direction == .outgoing && $0.location == nil }

        var ipToConnectionIDs: [String: [String]] = [:]
        for connection in unresolved {
            let host = IPAddress.normalizedHost(connection.remote.host)
            guard IPAddress.isIPAddress(host) else { continue }
            guard !IPAddress.isPrivateOrLocal(host, localAddresses: []) else { continue }
            ipToConnectionIDs[host, default: []].append(connection.id)
        }

        guard !ipToConnectionIDs.isEmpty else { return }
        let batchedTargets = Array(ipToConnectionIDs.keys.prefix(40))

        for ip in batchedTargets {
            if Task.isCancelled { return }
            guard let location = await geoService.lookup(ip: ip) else { continue }
            let connectionIDs = ipToConnectionIDs[ip] ?? []
            for connectionID in connectionIDs {
                if let idx = connections.firstIndex(where: { $0.id == connectionID }) {
                    connections[idx].location = location
                }
                updateHistoryLocation(connectionID: connectionID, location: location)
            }
        }
    }

    private func startGeoEnrichmentIfIdle() {
        guard geoEnrichmentTask == nil else { return }

        geoEnrichmentTask = Task { [weak self] in
            guard let self else { return }
            await self.enrichGeoIPIfNeeded()
            await MainActor.run {
                self.geoEnrichmentTask = nil
            }
        }
    }

    private func startThreatIntelIfIdle() {
        guard threatIntelTask == nil else { return }

        threatIntelTask = Task { [weak self] in
            guard let self else { return }
            await self.enrichThreatIntelIfNeeded()
            await MainActor.run {
                self.threatIntelTask = nil
            }
        }
    }

    private func appendHistory(from connections: [NetworkConnection]) {
        let now = Date()
        let dedupeWindow = max(historyDedupWindowSeconds, refreshInterval * 1.5)
        var newEntries: [HistoricalConnection] = []
        newEntries.reserveCapacity(connections.count)

        for (offset, connection) in connections.enumerated() {
            if let lastSeen = lastHistoryEventByConnectionID[connection.id],
               now.timeIntervalSince(lastSeen) < dedupeWindow {
                continue
            }
            lastHistoryEventByConnectionID[connection.id] = now

            newEntries.append(
                HistoricalConnection(
                    id: "\(connection.id)-\(Int(now.timeIntervalSince1970 * 1000))-\(offset)",
                    capturedAt: connection.capturedAt,
                    connection: connection
                )
            )
        }

        guard !newEntries.isEmpty else {
            pruneHistory(now: now)
            return
        }

        // Keep history chronological (oldest -> newest) for cheap appends.
        historyConnections.append(contentsOf: newEntries)
        pruneHistory(now: now)
    }

    private func pruneHistory(now: Date) {
        let cutoff = now.addingTimeInterval(-historyWindowSeconds)
        if let firstValid = historyConnections.firstIndex(where: { $0.capturedAt >= cutoff }), firstValid > 0 {
            historyConnections.removeFirst(firstValid)
        } else if historyConnections.last?.capturedAt ?? now < cutoff {
            historyConnections.removeAll(keepingCapacity: true)
        }
        if historyConnections.count > historyHardLimit {
            historyConnections.removeFirst(historyConnections.count - historyHardLimit)
        }

        // Keep dedupe map bounded to recent ids only.
        lastHistoryEventByConnectionID = lastHistoryEventByConnectionID.filter { _, ts in
            now.timeIntervalSince(ts) <= historyWindowSeconds
        }
    }

    private func updateHistoryLocation(connectionID: String, location: String) {
        for index in historyConnections.indices where historyConnections[index].connection.id == connectionID {
            historyConnections[index].connection.location = location
        }
        for index in frozenHistoryConnections.indices where frozenHistoryConnections[index].connection.id == connectionID {
            frozenHistoryConnections[index].connection.location = location
        }
    }

    func riskScore(for connection: NetworkConnection) -> Int {
        riskAssessment(for: connection).score
    }

    func riskReasons(for connection: NetworkConnection) -> [String] {
        riskAssessment(for: connection).reasons
    }

    private func riskAssessment(for connection: NetworkConnection) -> ThreatIntelAssessment {
        if let cached = riskAssessmentCache[connection.id] {
            return cached
        }

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

        if let intel = threatVerdict(for: connection), intel.malicious {
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
        let assessment = ThreatIntelAssessment(
            score: normalizedScore,
            autoSuspicious: normalizedScore >= 70,
            reasons: reasons,
            source: source,
            matchedIndicator: matchedIndicator
        )
        riskAssessmentCache[connection.id] = assessment
        return assessment
    }

    private func lightweightRiskScore(for connection: NetworkConnection) -> Int {
        var score = 0
        if connection.direction == .outgoing { score += 12 }

        let host = IPAddress.normalizedHost(connection.remote.host)
        if IPAddress.isIPAddress(host), !IPAddress.isPrivateOrLocal(host, localAddresses: []) { score += 8 }
        if let remotePort = connection.remote.port, suspiciousPorts.contains(remotePort) { score += 28 }
        if let intel = threatVerdict(for: connection), intel.malicious { score += max(65, intel.confidence) }
        if connection.direction == .outgoing, connection.location == nil, IPAddress.isIPAddress(host) { score += 6 }
        return max(0, min(score, 100))
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
            .compactMap { connection -> String? in
                let host = IPAddress.normalizedHost(connection.remote.host)
                guard !host.isEmpty, host != "*", !IPAddress.isPrivateOrLocal(host, localAddresses: []) else { return nil }
                return host
            }

        guard !targets.isEmpty else { return }

        var seenHosts = Set<String>()
        let uniqueTargets = targets.filter { host in
            if seenHosts.contains(host) { return false }
            seenHosts.insert(host)
            return true
        }.prefix(20)

        var shouldReapply = false
        var threatMessages: [String] = []

        for host in uniqueTargets {
            if Task.isCancelled { return }
            guard let verdict = await threatIntelService.lookupIndicator(host) else { continue }
            let now = Date()
            let previous = threatIntelByHost[host]?.verdict
            threatIntelByHost[host] = HostVerdictCacheEntry(verdict: verdict, updatedAt: now)
            if previous != verdict {
                shouldReapply = true
            }
            if verdict.malicious {
                threatMessages.append("Threat intel hit (\(verdict.source)): \(host) -> \(verdict.reason)")
            }
        }

        if shouldReapply {
            for message in threatMessages where !diagnostics.contains(message) {
                diagnostics.append(message)
            }
            reapplyRuleStatus()
        }
    }

    private func threatVerdict(for connection: NetworkConnection) -> ThreatFoxVerdict? {
        let host = IPAddress.normalizedHost(connection.remote.host)
        return threatIntelByHost[host]?.verdict
    }

    private func pruneThreatVerdicts(now: Date, activeConnections: [NetworkConnection]) {
        let activeHosts = Set(
            activeConnections.compactMap { connection -> String? in
                let host = IPAddress.normalizedHost(connection.remote.host)
                guard !host.isEmpty, host != "*" else { return nil }
                return host
            }
        )

        threatIntelByHost = threatIntelByHost.filter { host, entry in
            activeHosts.contains(host) || now.timeIntervalSince(entry.updatedAt) < threatVerdictTTL
        }
    }
}
