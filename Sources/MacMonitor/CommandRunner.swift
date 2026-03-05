import Foundation

protocol CommandRunning: Sendable {
    func run(_ launchPath: String, args: [String]) async -> String
}

struct ShellCommandRunner: CommandRunning, Sendable {
    func run(_ launchPath: String, args: [String]) async -> String {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: launchPath)
                process.arguments = args

                // Single pipe + background drain avoids deadlocks when output is large.
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = pipe
                let handle = pipe.fileHandleForReading

                do {
                    try process.run()
                    let timeoutWork = DispatchWorkItem {
                        if process.isRunning {
                            process.terminate()
                            Thread.sleep(forTimeInterval: 0.1)
                            if process.isRunning {
                                process.interrupt()
                            }
                        }
                    }
                    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5, execute: timeoutWork)

                    let captured = handle.readDataToEndOfFile()
                    timeoutWork.cancel()
                    process.waitUntilExit()
                    handle.closeFile()
                    let output = String(data: captured, encoding: .utf8) ?? ""
                    if output.isEmpty, process.terminationReason == .uncaughtSignal {
                        continuation.resume(returning: "[command-timeout]")
                    } else {
                        continuation.resume(returning: output)
                    }
                } catch {
                    handle.closeFile()
                    continuation.resume(returning: "")
                }
            }
        }
    }
}
