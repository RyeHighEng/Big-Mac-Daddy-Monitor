import Foundation
import Darwin

enum Formatters {
    static func bytesString(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(value), countStyle: .memory)
    }

    static func timestampString(_ date: Date) -> String {
        date.formatted(date: .omitted, time: .standard)
    }

    static func percentString(_ value: Double) -> String {
        let clamped = max(0, value)
        return String(format: "%.1f%%", clamped)
    }

    static func speedString(bytesPerSecond: UInt64) -> String {
        let text = ByteCountFormatter.string(fromByteCount: Int64(bytesPerSecond), countStyle: .file)
        return "\(text)/s"
    }

    static func speedCompactString(downloadBytesPerSecond: UInt64, uploadBytesPerSecond: UInt64) -> String {
        "↓\(shortBytes(downloadBytesPerSecond))/s ↑\(shortBytes(uploadBytesPerSecond))/s"
    }

    static func speedMiniString(downloadBytesPerSecond: UInt64, uploadBytesPerSecond: UInt64) -> String {
        "\(shortBytes(downloadBytesPerSecond))↓ \(shortBytes(uploadBytesPerSecond))↑"
    }

    private static func shortBytes(_ bytes: UInt64) -> String {
        let value = Double(bytes)
        if value >= 1_000_000_000 {
            return String(format: "%.1fG", value / 1_000_000_000)
        }
        if value >= 1_000_000 {
            return String(format: "%.1fM", value / 1_000_000)
        }
        if value >= 1_000 {
            return String(format: "%.1fK", value / 1_000)
        }
        return "\(bytes)B"
    }
}

enum IPAddress {
    static func normalizedHost(_ host: String) -> String {
        var result = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if result.hasPrefix("[") && result.hasSuffix("]") {
            result = String(result.dropFirst().dropLast())
        }
        return result
    }

    static func isIPv4(_ host: String) -> Bool {
        var addr = in_addr()
        return host.withCString { inet_pton(AF_INET, $0, &addr) } == 1
    }

    static func isIPv6(_ host: String) -> Bool {
        var addr = in6_addr()
        return host.withCString { inet_pton(AF_INET6, $0, &addr) } == 1
    }

    static func isIPAddress(_ host: String) -> Bool {
        let normalized = normalizedHost(host)
        return isIPv4(normalized) || isIPv6(normalized)
    }

    static func isPrivateOrLocal(_ host: String, localAddresses: Set<String>) -> Bool {
        let normalized = normalizedHost(host)
        if normalized == "*" || normalized == "0.0.0.0" || normalized == "::" {
            return true
        }
        if normalized == "127.0.0.1" || normalized == "::1" || normalized == "localhost" {
            return true
        }
        if localAddresses.contains(normalized) {
            return true
        }
        if isIPv4Private(normalized) {
            return true
        }
        if isIPv6Private(normalized) {
            return true
        }
        return false
    }

    private static func isIPv4Private(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }
        if parts[0] == 10 { return true }
        if parts[0] == 172 && (16...31).contains(parts[1]) { return true }
        if parts[0] == 192 && parts[1] == 168 { return true }
        if parts[0] == 169 && parts[1] == 254 { return true }
        if parts[0] == 100 && (64...127).contains(parts[1]) { return true }
        return false
    }

    private static func isIPv6Private(_ ip: String) -> Bool {
        let normalized = ip.lowercased()
        return normalized.hasPrefix("fc") ||
            normalized.hasPrefix("fd") ||
            normalized.hasPrefix("fe80") ||
            normalized == "::1"
    }
}

enum EndpointParser {
    static func parse(_ raw: String) -> Endpoint {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return Endpoint(host: "?", port: nil)
        }

        // [::1]:3000
        if trimmed.hasPrefix("[") {
            if let endBracket = trimmed.lastIndex(of: "]"),
               endBracket < trimmed.endIndex,
               let colon = trimmed[endBracket...].lastIndex(of: ":") {
                let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<endBracket])
                let port = Int(trimmed[trimmed.index(after: colon)...])
                return Endpoint(host: host, port: port)
            }
        }

        if let colon = trimmed.lastIndex(of: ":") {
            let host = String(trimmed[..<colon])
            let port = Int(trimmed[trimmed.index(after: colon)...])
            return Endpoint(host: IPAddress.normalizedHost(host), port: port)
        }

        return Endpoint(host: IPAddress.normalizedHost(trimmed), port: nil)
    }
}

enum DirectionClassifier {
    static func classify(
        local: Endpoint,
        remote: Endpoint,
        listeningPorts: Set<Int>,
        localAddresses: Set<String>
    ) -> TrafficDirection {
        let localHost = IPAddress.normalizedHost(local.host)
        let remoteHost = IPAddress.normalizedHost(remote.host)

        if IPAddress.isPrivateOrLocal(remoteHost, localAddresses: localAddresses) {
            return .local
        }
        if IPAddress.isPrivateOrLocal(localHost, localAddresses: localAddresses) == false {
            return .unknown
        }

        if let localPort = local.port,
           listeningPorts.contains(localPort),
           let remotePort = remote.port,
           remotePort >= 49152 {
            return .incoming
        }

        return .outgoing
    }
}

extension Sequence where Element == ProcessUsage {
    func topByCPU(limit: Int = 25) -> [ProcessUsage] {
        sorted { $0.cpuPercent > $1.cpuPercent }.prefix(limit).map { $0 }
    }

    func topByMemory(limit: Int = 25) -> [ProcessUsage] {
        sorted { $0.memoryBytes > $1.memoryBytes }.prefix(limit).map { $0 }
    }
}
