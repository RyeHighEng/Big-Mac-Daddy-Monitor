import Foundation

struct ThreatFoxVerdict: Sendable {
    let malicious: Bool
    let confidence: Int
    let reason: String
    let source: String
    let matchedIndicator: String?
}

actor ThreatIntelService {
    private struct CacheEntry {
        let verdict: ThreatFoxVerdict
        let expiresAt: Date
    }

    private let session: URLSession
    private let endpoint = URL(string: "https://threatfox-api.abuse.ch/api/v1/")!
    private var cache: [String: CacheEntry] = [:]
    private let cacheTTL: TimeInterval = 900

    init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 4
        config.timeoutIntervalForResource = 4
        self.session = URLSession(configuration: config)
    }

    func lookupIndicator(_ indicator: String) async -> ThreatFoxVerdict? {
        let normalized = indicator.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else { return nil }

        let now = Date()
        if let cached = cache[normalized], cached.expiresAt > now {
            return cached.verdict
        }

        guard let apiKey = SecretsResolver.threatFoxAPIKey() else {
            return nil
        }

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(apiKey, forHTTPHeaderField: "Auth-Key")
        request.httpBody = makeBody(for: normalized)

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else { return nil }
            guard let verdict = parseVerdict(from: data, fallbackIndicator: normalized) else { return nil }
            cache[normalized] = CacheEntry(verdict: verdict, expiresAt: now.addingTimeInterval(cacheTTL))
            return verdict
        } catch {
            return nil
        }
    }

    private func makeBody(for indicator: String) -> Data? {
        let payload: [String: String] = [
            "query": "search_ioc",
            "search_term": indicator
        ]
        return try? JSONSerialization.data(withJSONObject: payload, options: [])
    }

    private func parseVerdict(from data: Data, fallbackIndicator: String) -> ThreatFoxVerdict? {
        guard let object = try? JSONSerialization.jsonObject(with: data, options: []),
              let root = object as? [String: Any] else {
            return nil
        }

        let queryStatus = (root["query_status"] as? String ?? "").lowercased()
        if queryStatus.contains("no_result") {
            return ThreatFoxVerdict(
                malicious: false,
                confidence: 0,
                reason: "No known IOC match",
                source: "ThreatFox",
                matchedIndicator: nil
            )
        }

        guard let dataArray = root["data"] as? [[String: Any]], !dataArray.isEmpty else {
            return nil
        }

        let match = dataArray.first ?? [:]
        let confidenceText = (match["confidence_level"] as? String) ?? "75"
        let confidence = Int(confidenceText) ?? 75
        let ioc = match["ioc"] as? String ?? fallbackIndicator
        let threatType = match["threat_type_desc"] as? String ?? (match["threat_type"] as? String ?? "Known malicious IOC")
        let malware = match["malware_printable"] as? String
        let reason = malware.map { "\(threatType) (\($0))" } ?? threatType

        return ThreatFoxVerdict(
            malicious: true,
            confidence: max(1, min(confidence, 100)),
            reason: reason,
            source: "ThreatFox",
            matchedIndicator: ioc
        )
    }
}

enum SecretsResolver {
    static func threatFoxAPIKey() -> String? {
        if let direct = ProcessInfo.processInfo.environment["THREATFOX_API_KEY"]?.trimmedNonEmpty {
            return direct
        }

        let fileCandidates = candidateEnvFiles()

        for path in fileCandidates {
            guard let contents = try? String(contentsOf: path, encoding: .utf8) else { continue }
            if let value = envValue(named: "THREATFOX_API_KEY", in: contents) {
                return value
            }
        }

        return nil
    }

    private static func candidateEnvFiles() -> [URL] {
        var candidates: [URL] = []
        var seen = Set<String>()

        func appendUnique(_ url: URL) {
            let path = url.standardizedFileURL.path
            if seen.insert(path).inserted {
                candidates.append(url)
            }
        }

        // 1) Shell-launched app from repo root.
        appendUnique(URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(".env"))

        // 2) Packaged app in <project>/dist/<App>.app -> resolve project root .env.
        let bundleURL = Bundle.main.bundleURL
        let distDir = bundleURL.deletingLastPathComponent()
        let projectRoot = distDir.deletingLastPathComponent()
        appendUnique(projectRoot.appendingPathComponent(".env"))

        // 3) User-level persistent config.
        appendUnique(URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".config/mac-monitor/.env"))

        return candidates
    }

    private static func envValue(named key: String, in contents: String) -> String? {
        for line in contents.split(separator: "\n") {
            let raw = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if raw.isEmpty || raw.hasPrefix("#") { continue }
            guard let eq = raw.firstIndex(of: "=") else { continue }
            let keyPart = raw[..<eq].trimmingCharacters(in: .whitespacesAndNewlines)
            let k = keyPart.replacingOccurrences(of: "export ", with: "")
            guard k == key else { continue }
            let value = raw[raw.index(after: eq)...].trimmingCharacters(in: .whitespacesAndNewlines)
            return value.trimmingCharacters(in: CharacterSet(charactersIn: "\"'")).trimmedNonEmpty
        }
        return nil
    }
}

private extension String {
    var trimmedNonEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
