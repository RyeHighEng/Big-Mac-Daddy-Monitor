import Foundation

actor GeoIPService {
    private struct GeoResponse: Decodable {
        let success: Bool?
        let country: String?
        let region: String?
        let city: String?
        let ip: String?
    }

    private var cache: [String: String] = [:]

    func lookup(ip: String) async -> String? {
        if let cached = cache[ip] {
            return cached
        }

        guard let url = URL(string: "https://ipwho.is/\(ip)") else {
            return nil
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 3

        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            let response = try JSONDecoder().decode(GeoResponse.self, from: data)
            guard response.success != false else {
                cache[ip] = "Unknown"
                return cache[ip]
            }

            let segments = [response.city, response.region, response.country]
                .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }

            let location = segments.isEmpty ? "Unknown" : segments.joined(separator: ", ")
            cache[ip] = location
            return location
        } catch {
            return nil
        }
    }
}
