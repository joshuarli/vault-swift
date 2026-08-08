import VaultCore

private let standardInput: Int32 = 0
private let standardOutput: Int32 = 1
private let standardError: Int32 = 2

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

struct VaultCommand {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let first = arguments.first else {
            write(usage, to: standardOutput)
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
            write(usage, to: standardOutput)
        default:
            execute(arguments: arguments)
        }
    }

    private static func set(arguments: [String], silent: Bool) {
        requireExactArguments(arguments, command: silent ? "isset" : "set", count: 2)
        let name = arguments[1]

        do {
            let value = try readSecret(name: name, silent: silent)
            try KeychainStore().setSecret(name: name, value: Array(value.utf8))
        } catch {
            fail(String(describing: error))
        }
    }

    private static func get(arguments: [String]) {
        requireExactArguments(arguments, command: "get", count: 2)
        do {
            let value = try KeychainStore().secret(named: arguments[1])
            write(value + "\n", to: standardOutput)
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
            guard !names.isEmpty else {
                return
            }
            write(names.joined(separator: "\n") + "\n", to: standardOutput)
        } catch {
            fail(String(describing: error))
        }
    }

    private static func purge() {
        do {
            let count = try KeychainStore().purgeSecrets()
            if count == 0 {
                write("nothing to purge\n", to: standardOutput)
            } else {
                write("purged \(count) secret\(count == 1 ? "" : "s")\n", to: standardOutput)
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
        let commandArguments = Array(arguments[(separator + 1)...])
        guard let command = commandArguments.first else {
            fail("vault: missing command")
        }

        let store = KeychainStore()
        var overrides: [(String, String)] = []
        for rawSpecification in specifications {
            switch EnvironmentSpecification(rawSpecification) {
            case let .literal(name, value):
                overrides.append((name, value))
            case let .keychain(name):
                do {
                    overrides.append((name, try store.secret(named: name)))
                } catch {
                    fail(String(describing: error))
                }
            }
        }

        spawn(command: command, arguments: commandArguments, overrides: overrides)
    }

    private static func spawn(
        command: String,
        arguments: [String],
        overrides: [(String, String)]
    ) -> Never {
        var cArguments = unsafe [UnsafeMutablePointer<CChar>?]()
        unsafe cArguments.reserveCapacity(arguments.count + 1)
        for argument in arguments {
            guard let pointer = unsafe argument.withCString({ unsafe cDuplicate($0) }) else {
                fail("vault: failed to prepare command")
            }
            unsafe cArguments.append(pointer)
        }
        unsafe cArguments.append(nil)

        for (name, value) in overrides {
            let result = unsafe name.withCString { namePointer in
                unsafe value.withCString { valuePointer in
                    unsafe cSetEnvironment(namePointer, valuePointer, 1)
                }
            }
            guard result == 0 else {
                fail("vault: failed to set environment")
            }
        }

        let environment = unsafe cGetEnvironment()
        var child: Int32 = 0
        let spawnStatus = unsafe command.withCString { commandPointer in
            unsafe cArguments.withUnsafeMutableBufferPointer { buffer in
                unsafe cSpawn(
                    &child,
                    commandPointer,
                    nil,
                    nil,
                    buffer.baseAddress,
                    environment
                )
            }
        }
        guard spawnStatus == 0 else {
            fail("vault: failed to spawn command")
        }

        var waitStatus: Int32 = 0
        var waitResult: Int32
        repeat {
            waitResult = unsafe cWait(child, &waitStatus, 0)
        } while waitResult == -1 && errnoValue() == Posix.interrupted

        guard waitResult == child else {
            fail("vault: failed waiting for command")
        }

        let signal = waitStatus & 0x7F
        if signal != 0 && signal != 0x7F {
            cExit(128 + signal)
        }
        cExit((waitStatus >> 8) & 0xFF)
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
        if cIsATTY(standardInput) == 1 {
            if !silent {
                write("Enter value for \(name): ", to: standardError)
            }
            return try readWithoutEcho(silent: silent)
        }

        return try decodeInput(readAll())
    }

    /// Read terminal bytes with echo disabled, restoring the terminal before
    /// returning an input error so a failed read cannot leave the user's shell
    /// in raw mode.
    private static func readWithoutEcho(silent: Bool) throws -> String {
        var original = PosixTermios()
        guard unsafe cTCGetAttributes(standardInput, &original) == 0 else {
            return try decodeInput(readAll())
        }

        var modified = original
        let echoFlags = Posix.echo | Posix.echoNewline | Posix.canonical
        modified.c_lflag &= ~echoFlags
        _ = unsafe withUnsafePointer(to: &modified) {
            unsafe cTCSetAttributes(standardInput, Posix.terminalNow, $0)
        }
        defer {
            unsafe _ = withUnsafePointer(to: &original) {
                unsafe cTCSetAttributes(standardInput, Posix.terminalNow, $0)
            }
        }

        var bytes: [UInt8] = []
        var byte: UInt8 = 0
        while true {
            let count = unsafe withUnsafeMutablePointer(to: &byte) { pointer in
                unsafe cRead(standardInput, pointer, 1)
            }
            guard count == 1 else {
                throw InputError.readFailed
            }

            switch byte {
            case 10, 13:
                if !silent {
                    write("\n", to: standardError)
                }
                return try decodeInput(bytes)
            case 0x7F:
                if !bytes.isEmpty {
                    bytes.removeLast()
                    if !silent {
                        write("\u{8} \u{8}", to: standardError)
                    }
                }
            default:
                bytes.append(byte)
                if !silent {
                    write("*", to: standardError)
                }
            }
        }
    }

    private static func readAll() throws -> [UInt8] {
        var result: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = unsafe buffer.withUnsafeMutableBytes { bytes in
                unsafe cRead(standardInput, bytes.baseAddress, bytes.count)
            }
            if count == 0 {
                return result
            }
            if count < 0 {
                if errnoValue() == Posix.interrupted {
                    continue
                }
                throw InputError.readFailed
            }
            result.append(contentsOf: buffer.prefix(Int(count)))
        }
    }

    private static func decodeInput(_ bytes: [UInt8]) throws -> String {
        guard let value = decodeUTF8(bytes) else {
            throw InputError.invalidUTF8
        }
        return stripTrailingLineEndings(value)
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

private func decodeUTF8(_ bytes: [UInt8]) -> String? {
    var index = 0
    while index < bytes.count {
        let first = bytes[index]
        if first < 0x80 {
            index += 1
            continue
        }
        if first >= 0xC2 && first <= 0xDF {
            guard index + 1 < bytes.count, isContinuation(bytes[index + 1]) else {
                return nil
            }
            index += 2
            continue
        }
        if first >= 0xE0 && first <= 0xEF {
            guard index + 2 < bytes.count,
                  isContinuation(bytes[index + 1]),
                  isContinuation(bytes[index + 2]),
                  !(first == 0xE0 && bytes[index + 1] < 0xA0),
                  !(first == 0xED && bytes[index + 1] >= 0xA0) else {
                return nil
            }
            index += 3
            continue
        }
        if first >= 0xF0 && first <= 0xF4 {
            guard index + 3 < bytes.count,
                  isContinuation(bytes[index + 1]),
                  isContinuation(bytes[index + 2]),
                  isContinuation(bytes[index + 3]),
                  !(first == 0xF0 && bytes[index + 1] < 0x90),
                  !(first == 0xF4 && bytes[index + 1] >= 0x90) else {
                return nil
            }
            index += 4
            continue
        }
        return nil
    }
    return String(decoding: bytes, as: UTF8.self)
}

private func isContinuation(_ byte: UInt8) -> Bool {
    byte >= 0x80 && byte <= 0xBF
}

private func stripTrailingLineEndings(_ value: String) -> String {
    var scalars = value.unicodeScalars
    if scalars.last?.value == 0x0A {
        scalars.removeLast()
    }
    if scalars.last?.value == 0x0D {
        scalars.removeLast()
    }
    return String(scalars)
}

private func write(_ value: String, to descriptor: Int32) {
    write(Array(value.utf8), to: descriptor)
}

private func write(_ bytes: [UInt8], to descriptor: Int32) {
    var offset = 0
    unsafe bytes.withUnsafeBytes { buffer in
        while offset < bytes.count {
            let count = unsafe cWrite(
                descriptor,
                buffer.baseAddress!.advanced(by: offset),
                bytes.count - offset
            )
            if count <= 0 {
                return
            }
            offset += count
        }
    }
}

private func fail(_ message: String) -> Never {
    write(message + "\n", to: standardError)
    cExit(1)
}

private func errnoValue() -> Int32 {
    unsafe cErrno().pointee
}

VaultCommand.main()
