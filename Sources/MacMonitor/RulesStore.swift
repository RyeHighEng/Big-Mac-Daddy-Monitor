import Foundation

final class RulesStore {
    private let key = "mac-monitor.rules"
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func load() -> [TrafficRule] {
        guard let data = defaults.data(forKey: key) else { return [] }
        do {
            return try JSONDecoder().decode([TrafficRule].self, from: data)
        } catch {
            return []
        }
    }

    func save(_ rules: [TrafficRule]) {
        do {
            let data = try JSONEncoder().encode(rules)
            defaults.set(data, forKey: key)
        } catch {
            defaults.removeObject(forKey: key)
        }
    }
}
