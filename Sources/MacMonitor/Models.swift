import Foundation

enum TrafficDirection: String, CaseIterable, Codable {
    case outgoing = "Outgoing"
    case incoming = "Incoming"
    case local = "Local"
    case unknown = "Unknown"
}

enum TrafficStatus: String, CaseIterable, Codable {
    case normal = "Normal"
    case ignored = "Ignored"
    case suspicious = "Suspicious"
}

struct Endpoint: Hashable, Codable {
    var host: String
    var port: Int?

    var displayText: String {
        guard let port else { return host }
        return "\(host):\(port)"
    }
}

struct NetworkConnection: Identifiable, Hashable {
    let id: String
    let process: String
    let pid: Int
    let user: String
    let proto: String
    let local: Endpoint
    let remote: Endpoint
    let state: String
    let direction: TrafficDirection
    let capturedAt: Date
    var location: String?
    var status: TrafficStatus

    var processDisplay: String {
        "\(process) (\(pid))"
    }
}

struct HistoricalConnection: Identifiable, Hashable {
    let id: String
    let capturedAt: Date
    var connection: NetworkConnection
}

struct ThreatIntelAssessment: Hashable {
    let score: Int
    let autoSuspicious: Bool
    let reasons: [String]
    let source: String?
    let matchedIndicator: String?
}

struct PortRecord: Identifiable, Hashable {
    let id: String
    let process: String
    let pid: Int
    let user: String
    let proto: String
    let endpoint: Endpoint
    let state: String

    var processDisplay: String {
        "\(process) (\(pid))"
    }
}

struct ProcessUsage: Identifiable, Hashable {
    let id: Int
    let pid: Int
    let processName: String
    let cpuPercent: Double
    let memoryBytes: UInt64
    let path: String?
}

struct SystemSummary: Hashable {
    let cpuPercent: Double
    let usedMemoryBytes: UInt64
    let freeMemoryBytes: UInt64
    let totalMemoryBytes: UInt64
    let downloadBytesPerSecond: UInt64
    let uploadBytesPerSecond: UInt64
}

struct InterfaceRecord: Identifiable, Hashable {
    let id: String
    let name: String
    let family: String
    let address: String
    let netmask: String?
    let isUp: Bool
    let isLoopback: Bool
}

enum RuleType: String, CaseIterable, Codable {
    case ignore = "Ignore"
    case suspicious = "Suspicious"
}

struct TrafficRule: Identifiable, Hashable, Codable {
    let id: UUID
    var type: RuleType
    var processContains: String
    var remoteHostContains: String
    var remotePort: Int?
    var note: String
    var createdAt: Date

    init(
        id: UUID = UUID(),
        type: RuleType,
        processContains: String,
        remoteHostContains: String,
        remotePort: Int?,
        note: String,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.type = type
        self.processContains = processContains
        self.remoteHostContains = remoteHostContains
        self.remotePort = remotePort
        self.note = note
        self.createdAt = createdAt
    }

    func matches(_ connection: NetworkConnection) -> Bool {
        let processMatch = processContains.isEmpty || connection.process.localizedCaseInsensitiveContains(processContains)
        let hostMatch = remoteHostContains.isEmpty || connection.remote.host.localizedCaseInsensitiveContains(remoteHostContains)
        let portMatch = remotePort == nil || remotePort == connection.remote.port
        return processMatch && hostMatch && portMatch
    }
}

struct DataSnapshot {
    let connections: [NetworkConnection]
    let ports: [PortRecord]
    let summary: SystemSummary
    let processes: [ProcessUsage]
    let interfaces: [InterfaceRecord]
    let warnings: [String]
}
