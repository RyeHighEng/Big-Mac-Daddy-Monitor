import Foundation
import Darwin

struct SystemStatsProvider {
    struct CPUCapture {
        let user: UInt64
        let system: UInt64
        let idle: UInt64
        let nice: UInt64
    }

    static func captureCPU() -> CPUCapture? {
        var info = host_cpu_load_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info_data_t>.stride / MemoryLayout<integer_t>.stride)

        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, rebound, &count)
            }
        }

        guard result == KERN_SUCCESS else { return nil }
        return CPUCapture(
            user: UInt64(info.cpu_ticks.0),
            system: UInt64(info.cpu_ticks.1),
            idle: UInt64(info.cpu_ticks.2),
            nice: UInt64(info.cpu_ticks.3)
        )
    }

    static func cpuPercent(current: CPUCapture, previous: CPUCapture?) -> Double {
        guard let previous else {
            let active = current.user + current.system + current.nice
            let total = active + current.idle
            guard total > 0 else { return 0 }
            return (Double(active) / Double(total)) * 100
        }

        let user = current.user - previous.user
        let system = current.system - previous.system
        let nice = current.nice - previous.nice
        let idle = current.idle - previous.idle

        let active = user + system + nice
        let total = active + idle
        guard total > 0 else { return 0 }
        return (Double(active) / Double(total)) * 100
    }

    static func memorySummary() -> (used: UInt64, free: UInt64, total: UInt64)? {
        var vmStats = vm_statistics64_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.stride / MemoryLayout<integer_t>.stride)

        let result = withUnsafeMutablePointer(to: &vmStats) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                host_statistics64(mach_host_self(), HOST_VM_INFO64, rebound, &count)
            }
        }

        guard result == KERN_SUCCESS else { return nil }

        var pageSize: vm_size_t = 0
        guard host_page_size(mach_host_self(), &pageSize) == KERN_SUCCESS else { return nil }

        let totalMemory = ProcessInfo.processInfo.physicalMemory
        let freePages = UInt64(vmStats.free_count + vmStats.speculative_count)
        let freeBytes = freePages * UInt64(pageSize)
        let usedBytes = totalMemory > freeBytes ? (totalMemory - freeBytes) : 0

        return (used: usedBytes, free: freeBytes, total: totalMemory)
    }
}
