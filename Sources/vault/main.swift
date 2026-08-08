private let standardInput: Int32 = 0
private let standardOutput: Int32 = 1
private let standardError: Int32 = 2
private let keychainItemNotFound: Int32 = -25300

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
    @unsafe static func main() {
        let argumentCount = Int(CommandLine.argc)
        let argumentVector = unsafe CommandLine.unsafeArgv
        guard argumentCount > 1, let firstPointer = unsafe argumentVector[1] else {
            write(usage, to: standardOutput)
            return
        }
        let first = unsafe String(cString: firstPointer)

        switch first {
        case "set":
            unsafe set(argv: argumentVector, argc: argumentCount, silent: false)
        case "isset":
            unsafe set(argv: argumentVector, argc: argumentCount, silent: true)
        case "get":
            unsafe get(argv: argumentVector, argc: argumentCount)
        case "rm":
            unsafe remove(argv: argumentVector, argc: argumentCount)
        case "ls":
            unsafe list(argv: argumentVector, argc: argumentCount)
        case "purge":
            purge()
        case "-h", "--help", "help":
            write(usage, to: standardOutput)
        default:
            unsafe execute(argv: argumentVector, argc: argumentCount)
        }
    }

    @unsafe private static func set(
        argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        argc: Int,
        silent: Bool
    ) {
        unsafe requireExactArguments(argv, argc: argc, command: silent ? "isset" : "set", count: 2)
        let name = unsafe argument(argv, at: 2)

        do {
            let value = try readSecret(name: name, silent: silent)
            unsafe keychainSet(name: name, value: Array(value.utf8))
        } catch {
            fail(String(describing: error))
        }
    }

    @unsafe private static func get(
        argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        argc: Int
    ) {
        unsafe requireExactArguments(argv, argc: argc, command: "get", count: 2)
        let name = unsafe argument(argv, at: 2)
        let value = unsafe keychainGet(name: name)
        write(value, to: standardOutput)
        write("\n", to: standardOutput)
    }

    @unsafe private static func remove(
        argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        argc: Int
    ) {
        unsafe requireExactArguments(argv, argc: argc, command: "rm", count: 2)
        let name = unsafe argument(argv, at: 2)
        unsafe keychainDelete(name: name)
    }

    @unsafe private static func list(
        argv _: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        argc: Int
    ) {
        guard argc == 2 else {
            fail("vault: ls takes no arguments")
        }
        for name in unsafe keychainList() {
            write(name, to: standardOutput)
            write("\n", to: standardOutput)
        }
    }

    private static func purge() {
        let count = unsafe keychainPurge()
        if count == 0 {
            write("nothing to purge\n", to: standardOutput)
        } else {
            write("purged \(count) secret\(count == 1 ? "" : "s")\n", to: standardOutput)
        }
    }

    @unsafe private static func execute(
        argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        argc: Int
    ) {
        var separator = 0
        while separator < argc && !(unsafe isSeparator(unsafe argv[separator]!)) {
            separator += 1
        }
        guard separator < argc else {
            fail("vault: expected '--' before command")
        }

        let commandIndex = separator + 1
        guard commandIndex < argc else {
            fail("vault: missing command")
        }

        for index in 1..<separator {
            let rawSpecification = unsafe argument(argv, at: index)
            switch EnvironmentSpec(rawSpecification) {
            case let .literal(name, value):
                setEnvironment(name: name, value: value)
            case let .keychain(name):
                setEnvironment(name: name, value: unsafe keychainGet(name: name))
            }
        }

        unsafe spawn(argv: argv, commandIndex: commandIndex)
    }

    @unsafe private static func spawn(
        argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        commandIndex: Int
    ) -> Never {
        let environment = unsafe cGetEnvironment()
        var child: Int32 = 0
        let childArguments = unsafe argv.advanced(by: commandIndex)
        let commandPointer = unsafe childArguments.pointee!
        let spawnStatus = unsafe cSpawn(
            &child,
            UnsafePointer(commandPointer),
            nil,
            nil,
            childArguments,
            environment
        )
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

    @unsafe private static func requireExactArguments(
        _ argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        argc: Int,
        command: String,
        count: Int
    ) {
        guard argc - 1 >= count else {
            fail("vault: missing name for \(command)")
        }
        guard argc - 1 <= count else {
            let unexpected = unsafe argument(argv, at: count + 1)
            fail("vault: unexpected argument: \(unexpected)")
        }
        guard !(unsafe argument(argv, at: 2)).isEmpty else {
            fail("vault: empty name not allowed")
        }
    }

    @unsafe private static func argument(
        _ argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        at index: Int
    ) -> String {
        unsafe String(cString: unsafe argv[index]!)
    }

    @unsafe private static func isSeparator(_ pointer: UnsafeMutablePointer<CChar>) -> Bool {
        unsafe pointer[0] == 45 && pointer[1] == 45 && pointer[2] == 0
    }

    private static func setEnvironment(name: String, value: String) {
        let result = unsafe name.withCString { namePointer in
            unsafe value.withCString { valuePointer in
                unsafe cSetEnvironment(namePointer, valuePointer, 1)
            }
        }
        guard result == 0 else {
            fail("vault: failed to set environment")
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
        return stripInputLineEndings(value)
    }
}

@unsafe private func keychainSet(name: String, value: [UInt8]) {
    let status = unsafe value.withUnsafeBytes { bytes in
        unsafe name.withCString { namePointer in
            unsafe cKeychainSet(namePointer, bytes.baseAddress, value.count)
        }
    }
    guard status == 0 else {
        keychainFailure(action: "set", name: name, status: status)
    }
}

@unsafe private func keychainGet(name: String) -> String {
    var rawValue: UnsafeMutablePointer<UInt8>?
    var valueLength = 0
    let status = unsafe name.withCString { namePointer in
        unsafe cKeychainGet(namePointer, &rawValue, &valueLength)
    }
    guard status == 0 else {
        keychainFailure(action: "get", name: name, status: status)
    }
    defer {
        if let rawValue = unsafe rawValue {
            unsafe cKeychainFree(UnsafeMutableRawPointer(rawValue))
        }
    }

    let bytes: [UInt8]
    if let rawValue = unsafe rawValue {
        bytes = unsafe Array(unsafe UnsafeBufferPointer(start: rawValue, count: valueLength))
    } else {
        bytes = []
    }
    guard let value = decodeUTF8(bytes) else {
        fail("vault: invalid UTF-8 in \(name)")
    }
    return value
}

@unsafe private func keychainDelete(name: String) {
    let status = unsafe name.withCString { namePointer in
        unsafe cKeychainDelete(namePointer)
    }
    guard status == 0 else {
        keychainFailure(action: "delete", name: name, status: status)
    }
}

@unsafe private func keychainList() -> [String] {
    var rawNames: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
    var nameCount = 0
    let status = unsafe cKeychainList(&rawNames, &nameCount)
    guard status == 0 else {
        keychainFailure(action: "list", name: "", status: status)
    }
    guard let rawNames = unsafe rawNames else {
        return []
    }
    defer {
        unsafe cKeychainFree(UnsafeMutableRawPointer(rawNames))
    }

    var names: [String] = []
    names.reserveCapacity(nameCount)
    for index in 0..<nameCount {
        guard let rawName = unsafe rawNames[index] else {
            continue
        }
        names.append(unsafe String(cString: unsafe UnsafePointer(rawName)))
        unsafe cKeychainFree(UnsafeMutableRawPointer(rawName))
    }
    return names
}

@unsafe private func keychainPurge() -> Int {
    var count = 0
    let status = unsafe cKeychainPurge(&count)
    guard status == 0 else {
        keychainFailure(action: "purge", name: "", status: status)
    }
    return count
}

@unsafe private func keychainStatusMessage(_ status: Int32) -> String? {
    guard let rawMessage = unsafe cKeychainStatusMessage(status) else {
        return nil
    }
    defer {
        unsafe cKeychainFree(UnsafeMutableRawPointer(rawMessage))
    }
    return unsafe String(cString: unsafe UnsafePointer(rawMessage))
}

private func keychainFailure(action: String, name: String, status: Int32) -> Never {
    if status == keychainItemNotFound {
        if action == "get" {
            fail("vault: \(name): could not be found")
        }
        if action == "delete" {
            fail("vault: \(name): not found")
        }
    }
    let subject = name.isEmpty ? "vault:" : "vault: \(name):"
    let message = unsafe keychainStatusMessage(status) ?? "OSStatus \(status)"
    fail("\(subject) \(action) failed: \(message) (OSStatus \(status))")
}

private enum EnvironmentSpec {
    case keychain(name: String)
    case literal(name: String, value: String)

    init(_ specification: String) {
        if let equals = specification.firstIndex(of: "=") {
            let name = String(specification[..<equals])
            let value = String(specification[specification.index(after: equals)...])
            if !name.isEmpty && !value.contains("=") {
                self = .literal(name: name, value: value)
                return
            }
        }
        self = .keychain(name: specification)
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

private func stripInputLineEndings(_ value: String) -> String {
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

unsafe VaultCommand.main()
