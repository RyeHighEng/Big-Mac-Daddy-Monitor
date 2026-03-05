import Foundation
import Darwin
#if canImport(AppKit)
import AppKit
#endif

actor MonitorCollector {
    private struct NetworkCounter {
        let receivedBytes: UInt64
        let sentBytes: UInt64
        let sampledAt: Date
    }

    private let runner: CommandRunning
    private var previousCPUCapture: SystemStatsProvider.CPUCapture?
    private var previousNetworkCounter: NetworkCounter?

    init(runner: CommandRunning = ShellCommandRunner()) {
        self.runner = runner
    }

    func collectSnapshot() async -> DataSnapshot {
        var warnings: [String] = []
        let interfaces = collectInterfaces()
        let localAddresses = Set(interfaces.map { IPAddress.normalizedHost($0.address) }).union(["127.0.0.1", "::1", "localhost"])

        async let listeningTCPRaw = runner.run("/usr/sbin/lsof", args: ["-nP", "-iTCP", "-sTCP:LISTEN"])
        async let listeningUDPRaw = runner.run("/usr/sbin/lsof", args: ["-nP", "-iUDP"])
        async let establishedRaw = runner.run("/usr/sbin/lsof", args: ["-nP", "-iTCP", "-sTCP:ESTABLISHED"])

        let listeningTCPOutput = await listeningTCPRaw
        let listeningUDPOutput = await listeningUDPRaw
        let establishedOutput = await establishedRaw

        if isCollectionError(listeningTCPOutput) || isCollectionError(listeningUDPOutput) {
            warnings.append("Open ports may be incomplete (lsof permission denied or timed out).")
        }
        if isCollectionError(establishedOutput) {
            warnings.append("Network traffic may be incomplete (lsof permission denied or timed out).")
        }

        let ports = parsePorts(tcpOutput: listeningTCPOutput, udpOutput: listeningUDPOutput)
        let listeningPorts = Set(ports.compactMap { $0.endpoint.port })
        let connections = parseConnections(
            output: establishedOutput,
            listeningPorts: listeningPorts,
            localAddresses: localAddresses
        )

        async let processUsageRaw = runner.run("/bin/ps", args: ["-axo", "pid=,%cpu=,rss=,comm="])
        let processOutput = await processUsageRaw

        var processes = parseProcessUsage(output: processOutput)
        if processes.isEmpty {
            if isCollectionError(processOutput) {
                warnings.append("Process CPU/memory details unavailable (ps permission denied or timed out). Showing running apps fallback.")
            } else {
                warnings.append("Process CPU/memory details unavailable. Showing running apps fallback.")
            }
            processes = fallbackRunningApps()
        }

        let summary = makeSystemSummary()
        if summary.cpuPercent == 0 {
            warnings.append("CPU sampling returned 0%. If this persists, relaunch and allow monitoring permissions.")
        }

        return DataSnapshot(
            connections: connections,
            ports: ports,
            summary: summary,
            processes: processes,
            interfaces: interfaces,
            warnings: Array(Set(warnings)).sorted()
        )
    }

    private func parseConnections(
        output: String,
        listeningPorts: Set<Int>,
        localAddresses: Set<String>
    ) -> [NetworkConnection] {
        output
            .split(separator: "\n")
            .map(String.init)
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("COMMAND") }
            .compactMap { parseConnectionLine($0, listeningPorts: listeningPorts, localAddresses: localAddresses) }
            .sorted { lhs, rhs in
                if lhs.process == rhs.process {
                    return lhs.pid < rhs.pid
                }
                return lhs.process < rhs.process
            }
    }

    private func parseConnectionLine(
        _ line: String,
        listeningPorts: Set<Int>,
        localAddresses: Set<String>
    ) -> NetworkConnection? {
        let columns = line.split(whereSeparator: { $0.isWhitespace })
        guard columns.count >= 10 else { return nil }
        guard let pid = Int(columns[1]) else { return nil }
        guard let protoIndex = columns.firstIndex(where: { $0 == "TCP" || $0 == "UDP" }) else { return nil }

        let process = String(columns[0])
        let user = String(columns[2])
        let proto = String(columns[protoIndex])

        var endpointAndState = columns[(protoIndex + 1)...].joined(separator: " ")
        var state = "-"
        if let range = endpointAndState.range(of: #" \([A-Z_]+\)$"#, options: .regularExpression) {
            let stateText = endpointAndState[range].trimmingCharacters(in: CharacterSet(charactersIn: " ()"))
            state = stateText
            endpointAndState.removeSubrange(range)
        }

        let parts = endpointAndState.components(separatedBy: "->")
        guard let localRaw = parts.first else { return nil }
        let remoteRaw = parts.count > 1 ? parts[1] : "*"

        let local = EndpointParser.parse(localRaw)
        let remote = EndpointParser.parse(remoteRaw)
        let direction = DirectionClassifier.classify(
            local: local,
            remote: remote,
            listeningPorts: listeningPorts,
            localAddresses: localAddresses
        )

        let id = "\(process)-\(pid)-\(proto)-\(local.displayText)-\(remote.displayText)-\(state)"
        return NetworkConnection(
            id: id,
            process: process,
            pid: pid,
            user: user,
            proto: proto,
            local: local,
            remote: remote,
            state: state,
            direction: direction,
            capturedAt: Date(),
            location: nil,
            status: .normal
        )
    }

    private func parsePorts(tcpOutput: String, udpOutput: String) -> [PortRecord] {
        var result = [PortRecord]()
        let tcpLines = tcpOutput.split(separator: "\n").map(String.init)
        for line in tcpLines where !line.trimmingCharacters(in: .whitespaces).hasPrefix("COMMAND") {
            if let record = parsePortLine(line) {
                result.append(record)
            }
        }

        let udpLines = udpOutput.split(separator: "\n").map(String.init)
        for line in udpLines where !line.trimmingCharacters(in: .whitespaces).hasPrefix("COMMAND") {
            if let record = parsePortLine(line, fallbackProto: "UDP") {
                result.append(record)
            }
        }

        return Array(Set(result)).sorted { lhs, rhs in
            if lhs.endpoint.port == rhs.endpoint.port {
                return lhs.process < rhs.process
            }
            return (lhs.endpoint.port ?? 0) < (rhs.endpoint.port ?? 0)
        }
    }

    private func parsePortLine(_ line: String, fallbackProto: String? = nil) -> PortRecord? {
        let columns = line.split(whereSeparator: { $0.isWhitespace })
        guard columns.count >= 9 else { return nil }
        guard let pid = Int(columns[1]) else { return nil }

        let process = String(columns[0])
        let user = String(columns[2])

        let protoIndex = columns.firstIndex(where: { $0 == "TCP" || $0 == "UDP" })
        let proto: String
        let endpointColumnsStart: Int
        if let protoIndex {
            proto = String(columns[protoIndex])
            endpointColumnsStart = protoIndex + 1
        } else if let fallbackProto {
            proto = fallbackProto
            endpointColumnsStart = 8
        } else {
            return nil
        }

        let endpointAndState = columns[endpointColumnsStart...].joined(separator: " ")
        var state = "-"
        var endpointRaw = endpointAndState

        if let range = endpointAndState.range(of: #" \([A-Z_]+\)$"#, options: .regularExpression) {
            state = endpointAndState[range].trimmingCharacters(in: CharacterSet(charactersIn: " ()"))
            endpointRaw.removeSubrange(range)
        }

        if endpointRaw.contains("->") {
            endpointRaw = String(endpointRaw.split(separator: "->").first ?? "")
        }

        let endpoint = EndpointParser.parse(endpointRaw)
        let id = "\(process)-\(pid)-\(proto)-\(endpoint.displayText)-\(state)"

        return PortRecord(
            id: id,
            process: process,
            pid: pid,
            user: user,
            proto: proto,
            endpoint: endpoint,
            state: state
        )
    }

    private func parseProcessUsage(output: String) -> [ProcessUsage] {
        output
            .split(separator: "\n")
            .compactMap { parseProcessLine(String($0)) }
            .sorted { lhs, rhs in
                if lhs.cpuPercent == rhs.cpuPercent {
                    return lhs.memoryBytes > rhs.memoryBytes
                }
                return lhs.cpuPercent > rhs.cpuPercent
            }
    }

    private func makeSystemSummary() -> SystemSummary {
        let cpuCapture = SystemStatsProvider.captureCPU()
        let cpuPercent = {
            guard let cpuCapture else { return 0.0 }
            let value = SystemStatsProvider.cpuPercent(current: cpuCapture, previous: previousCPUCapture)
            previousCPUCapture = cpuCapture
            return value
        }()
        let throughput = currentNetworkThroughput()

        if let memory = SystemStatsProvider.memorySummary() {
            return SystemSummary(
                cpuPercent: cpuPercent,
                usedMemoryBytes: memory.used,
                freeMemoryBytes: memory.free,
                totalMemoryBytes: memory.total,
                downloadBytesPerSecond: throughput.downloadBytesPerSecond,
                uploadBytesPerSecond: throughput.uploadBytesPerSecond
            )
        }

        let total = ProcessInfo.processInfo.physicalMemory
        return SystemSummary(
            cpuPercent: cpuPercent,
            usedMemoryBytes: 0,
            freeMemoryBytes: total,
            totalMemoryBytes: total,
            downloadBytesPerSecond: throughput.downloadBytesPerSecond,
            uploadBytesPerSecond: throughput.uploadBytesPerSecond
        )
    }

    private func isCollectionError(_ output: String) -> Bool {
        let lower = output.lowercased()
        return lower.contains("operation not permitted")
            || lower.contains("not permitted")
            || lower.contains("permission denied")
            || lower.contains("not authorized")
            || lower.contains("sandbox")
            || lower.contains("[command-timeout]")
    }

    private func fallbackRunningApps() -> [ProcessUsage] {
#if canImport(AppKit)
        return NSWorkspace.shared.runningApplications
            .sorted { lhs, rhs in
                let left = lhs.localizedName ?? lhs.bundleIdentifier ?? "\(lhs.processIdentifier)"
                let right = rhs.localizedName ?? rhs.bundleIdentifier ?? "\(rhs.processIdentifier)"
                return left.localizedCaseInsensitiveCompare(right) == .orderedAscending
            }
            .map { app in
                let name = app.localizedName ?? app.bundleIdentifier ?? "Unknown"
                return ProcessUsage(
                    id: Int(app.processIdentifier),
                    pid: Int(app.processIdentifier),
                    processName: name,
                    cpuPercent: 0,
                    memoryBytes: 0,
                    path: app.executableURL?.path
                )
            }
#else
        return []
#endif
    }

    private func currentNetworkThroughput() -> (downloadBytesPerSecond: UInt64, uploadBytesPerSecond: UInt64) {
        guard let current = collectNetworkCounter() else {
            return (0, 0)
        }
        defer { previousNetworkCounter = current }

        guard let previous = previousNetworkCounter else {
            return (0, 0)
        }

        let elapsed = max(current.sampledAt.timeIntervalSince(previous.sampledAt), 0.001)
        let deltaDown = current.receivedBytes >= previous.receivedBytes ? current.receivedBytes - previous.receivedBytes : 0
        let deltaUp = current.sentBytes >= previous.sentBytes ? current.sentBytes - previous.sentBytes : 0

        return (
            downloadBytesPerSecond: UInt64(Double(deltaDown) / elapsed),
            uploadBytesPerSecond: UInt64(Double(deltaUp) / elapsed)
        )
    }

    private func collectNetworkCounter() -> NetworkCounter? {
        var ptr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ptr) == 0, let first = ptr else {
            return nil
        }
        defer { freeifaddrs(ptr) }

        var received: UInt64 = 0
        var sent: UInt64 = 0

        for cursor in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = cursor.pointee
            guard let address = ifa.ifa_addr else { continue }
            guard Int32(address.pointee.sa_family) == AF_LINK else { continue }

            let flags = Int32(ifa.ifa_flags)
            let isUp = (flags & IFF_UP) == IFF_UP
            let isLoopback = (flags & IFF_LOOPBACK) == IFF_LOOPBACK
            if !isUp || isLoopback { continue }

            guard let dataPointer = ifa.ifa_data?.assumingMemoryBound(to: if_data.self) else { continue }
            let data = dataPointer.pointee
            received += UInt64(data.ifi_ibytes)
            sent += UInt64(data.ifi_obytes)
        }

        return NetworkCounter(
            receivedBytes: received,
            sentBytes: sent,
            sampledAt: Date()
        )
    }

    private func parseProcessLine(_ line: String) -> ProcessUsage? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return nil }

        let components = trimmed.split(maxSplits: 3, omittingEmptySubsequences: true, whereSeparator: { $0.isWhitespace })
        guard components.count >= 4 else { return nil }

        guard let pid = Int(components[0]) else { return nil }
        guard let cpu = Double(components[1]) else { return nil }
        guard let rssKB = UInt64(components[2]) else { return nil }

        let commandPath = String(components[3])
        let processName = URL(fileURLWithPath: commandPath).lastPathComponent

        return ProcessUsage(
            id: pid,
            pid: pid,
            processName: processName,
            cpuPercent: cpu,
            memoryBytes: rssKB * 1024,
            path: commandPath
        )
    }

    private func collectInterfaces() -> [InterfaceRecord] {
        var records: [InterfaceRecord] = []

        var ptr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ptr) == 0, let first = ptr else {
            return []
        }
        defer { freeifaddrs(ptr) }

        for cursor in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = cursor.pointee
            guard let address = ifa.ifa_addr else { continue }

            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }

            guard let nameCString = ifa.ifa_name else { continue }
            let name = String(cString: nameCString)

            let addrString = socketAddressToString(address) ?? "?"
            let maskString = socketAddressToString(ifa.ifa_netmask)

            let flags = Int32(ifa.ifa_flags)
            let isUp = (flags & IFF_UP) == IFF_UP
            let isLoopback = (flags & IFF_LOOPBACK) == IFF_LOOPBACK
            let familyName = family == AF_INET ? "IPv4" : "IPv6"

            let id = "\(name)-\(familyName)-\(addrString)"
            records.append(
                InterfaceRecord(
                    id: id,
                    name: name,
                    family: familyName,
                    address: addrString,
                    netmask: maskString,
                    isUp: isUp,
                    isLoopback: isLoopback
                )
            )
        }

        return records.sorted { lhs, rhs in
            if lhs.name == rhs.name {
                return lhs.family < rhs.family
            }
            return lhs.name < rhs.name
        }
    }

    private func socketAddressToString(_ address: UnsafeMutablePointer<sockaddr>?) -> String? {
        guard let address else { return nil }

        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let length = socklen_t(address.pointee.sa_len)

        let result = getnameinfo(
            address,
            length,
            &host,
            socklen_t(host.count),
            nil,
            0,
            NI_NUMERICHOST
        )

        guard result == 0 else { return nil }
        let bytes = host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }
}
