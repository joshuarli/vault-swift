import Darwin
import Foundation
import VaultCore

private let usage = """
vault — macOS Keychain secret manager

Usage:

  vault set   <NAME>            Store a secret (prompts for value)
  vault isset <NAME>            Store a secret (silent, no prompt)
  vault get   <NAME>            Print a secret to stdout
  vault rm    <NAME>            Delete a secret
  vault ls                      List all stored secret names
  vault purge                   Delete every secret vault manages

  vault [ENV ...] -- <CMD> [ARGS ...]   Run CMD with secrets injected

Environment specifications before -- may be:

  KEY                          Look up KEY in the Keychain
  KEY=VALUE                    Pass literal KEY=VALUE

Examples:

  vault set OPENAI_API_KEY
  vault OPENAI_API_KEY DATABASE_URL RUST_LOG=debug -- cargo run
  vault -- cargo run
"""

@main
struct VaultCommand {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let first = arguments.first else {
            writeStandardOutput(usage)
            return
        }

        switch first {
        case "set":
            set(arguments: arguments, silent: false)
        case "isset":
            set(arguments: arguments, silent: true)
        case "get":
            get(arguments: arguments)
        case "rm":
            remove(arguments: arguments)
        case "ls":
            list(arguments: arguments)
        case "purge":
            purge()
        case "-h", "--help", "help":
            writeStandardOutput(usage)
        default:
            execute(arguments: arguments)
        }
    }

    private static func set(arguments: [String], silent: Bool) {
        requireExactArguments(arguments, command: silent ? "isset" : "set", count: 2)
        let name = arguments[1]

        do {
            let value = try readSecret(name: name, silent: silent)
            try KeychainStore().setSecret(name: name, value: Data(value.utf8))
        } catch {
            fail(String(describing: error))
        }
    }

    private static func get(arguments: [String]) {
        requireExactArguments(arguments, command: "get", count: 2)
        do {
            let value = try KeychainStore().secret(named: arguments[1])
            writeStandardOutput(value + "\n")
        } catch {
            fail(String(describing: error))
        }
    }

    private static func remove(arguments: [String]) {
        requireExactArguments(arguments, command: "rm", count: 2)
        do {
            try KeychainStore().deleteSecret(named: arguments[1])
        } catch {
            fail(String(describing: error))
        }
    }

    private static func list(arguments: [String]) {
        guard arguments.count == 1 else {
            fail("vault: ls takes no arguments")
        }
        do {
            let names = try KeychainStore().listSecrets()
            writeStandardOutput(names.joined(separator: "\n") + (names.isEmpty ? "" : "\n"))
        } catch {
            fail(String(describing: error))
        }
    }

    private static func purge() {
        do {
            let count = try KeychainStore().purgeSecrets()
            if count == 0 {
                writeStandardOutput("nothing to purge\n")
            } else {
                writeStandardOutput("purged \(count) secret\(count == 1 ? "" : "s")\n")
            }
        } catch {
            fail(String(describing: error))
        }
    }

    private static func execute(arguments: [String]) {
        guard let separator = arguments.firstIndex(of: "--") else {
            fail("vault: expected '--' before command")
        }

        let specifications = arguments[..<separator]
        let commandArguments = arguments[(separator + 1)...]
        guard let command = commandArguments.first else {
            fail("vault: missing command")
        }

        var environment = ProcessInfo.processInfo.environment
        let store = KeychainStore()
        for rawSpecification in specifications {
            switch EnvironmentSpecification(rawSpecification) {
            case let .literal(name, value):
                environment[name] = value
            case let .keychain(name):
                do {
                    environment[name] = try store.secret(named: name)
                } catch {
                    fail(String(describing: error))
                }
            }
        }

        let executable = resolveExecutable(command, path: environment["PATH"])
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = Array(commandArguments.dropFirst())
        process.environment = environment
        process.standardInput = FileHandle.standardInput
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError

        do {
            try process.run()
        } catch {
            fail("vault: \(error)")
        }
        process.waitUntilExit()

        if process.terminationReason == .uncaughtSignal {
            exit(Int32(128 + Int(process.terminationStatus)))
        }
        exit(process.terminationStatus)
    }

    private static func requireExactArguments(
        _ arguments: [String],
        command: String,
        count: Int
    ) {
        guard arguments.count >= count else {
            fail("vault: missing name for \(command)")
        }
        guard arguments.count <= count else {
            fail("vault: unexpected argument: \(arguments[count])")
        }
        guard !arguments[1].isEmpty else {
            fail("vault: empty name not allowed")
        }
    }

    private static func readSecret(name: String, silent: Bool) throws -> String {
        if isatty(STDIN_FILENO) == 1 {
            if !silent {
                writeStandardError("Enter value for \(name): ")
            }
            return try readWithoutEcho(silent: silent)
        }

        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard let value = String(data: data, encoding: .utf8) else {
            throw InputError.invalidUTF8
        }
        return stripTrailingLineEndings(value)
    }

    /// Read terminal bytes with echo disabled, restoring the terminal before
    /// returning an input error so a failed read cannot leave the user's shell
    /// in raw mode.
    private static func readWithoutEcho(silent: Bool) throws -> String {
        var original = termios()
        guard unsafe tcgetattr(STDIN_FILENO, &original) == 0 else {
            return try readFallbackLine()
        }

        var modified = original
        let echoFlags = tcflag_t(ECHO) | tcflag_t(ECHONL) | tcflag_t(ICANON)
        modified.c_lflag &= ~echoFlags
        _ = unsafe tcsetattr(STDIN_FILENO, TCSANOW, &modified)
        defer { unsafe _ = tcsetattr(STDIN_FILENO, TCSANOW, &original) }

        var bytes: [UInt8] = []
        var byte: UInt8 = 0
        while true {
            let count = unsafe withUnsafeMutablePointer(to: &byte) { pointer in
                unsafe Darwin.read(STDIN_FILENO, pointer, 1)
            }
            guard count == 1 else {
                throw InputError.readFailed
            }

            switch byte {
            case UInt8(ascii: "\n"), UInt8(ascii: "\r"):
                if !silent {
                    writeStandardError("\n")
                }
                return try decodeInput(bytes)
            case 0x7f:
                if !bytes.isEmpty {
                    bytes.removeLast()
                    if !silent {
                        writeStandardError("\u{8} \u{8}")
                    }
                }
            default:
                bytes.append(byte)
                if !silent {
                    writeStandardError("*")
                }
            }
        }
    }

    private static func readFallbackLine() throws -> String {
        let data = FileHandle.standardInput.readData(ofLength: 4096)
        guard let value = String(data: data, encoding: .utf8) else {
            throw InputError.invalidUTF8
        }
        return stripTrailingLineEndings(value)
    }

    private static func decodeInput(_ bytes: [UInt8]) throws -> String {
        guard let value = String(data: Data(bytes), encoding: .utf8) else {
            throw InputError.invalidUTF8
        }
        return value
    }
}

private enum InputError: Error, CustomStringConvertible {
    case invalidUTF8
    case readFailed

    var description: String {
        switch self {
        case .invalidUTF8:
            return "vault: failed to read stdin: invalid UTF-8"
        case .readFailed:
            return "vault: failed to read input"
        }
    }
}

private func resolveExecutable(_ command: String, path: String?) -> String {
    if command.contains("/") {
        return command
    }

    let searchPath = path ?? "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    for directory in searchPath.split(separator: ":", omittingEmptySubsequences: false) {
        let candidate = directory.isEmpty ? command : "\(directory)/\(command)"
        if FileManager.default.isExecutableFile(atPath: candidate) {
            return candidate
        }
    }
    return command
}

private func writeStandardOutput(_ value: String) {
    FileHandle.standardOutput.write(Data(value.utf8))
}

private func writeStandardError(_ value: String) {
    FileHandle.standardError.write(Data(value.utf8))
}

private func fail(_ message: String) -> Never {
    writeStandardError(message + "\n")
    exit(1)
}
