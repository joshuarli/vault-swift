import CSystem

typealias CInt = Int32
typealias PosixTermios = termios

enum Posix {
    static var echo: tcflag_t { tcflag_t(ECHO) }
    static var echoNewline: tcflag_t { tcflag_t(ECHONL) }
    static var canonical: tcflag_t { tcflag_t(ICANON) }
    static var terminalNow: CInt { TCSANOW }
    static var interrupted: CInt { EINTR }
}

@inline(__always)
func cRead(_ descriptor: CInt, _ buffer: UnsafeMutableRawPointer?, _ count: Int) -> Int {
    unsafe read(descriptor, buffer, count)
}

@inline(__always)
func cWrite(_ descriptor: CInt, _ buffer: UnsafeRawPointer?, _ count: Int) -> Int {
    unsafe write(descriptor, buffer, count)
}

@inline(__always)
func cIsATTY(_ descriptor: CInt) -> CInt {
    isatty(descriptor)
}

@inline(__always)
func cTCGetAttributes(_ descriptor: CInt, _ attributes: UnsafeMutablePointer<PosixTermios>) -> CInt {
    unsafe tcgetattr(descriptor, attributes)
}

@inline(__always)
func cTCSetAttributes(_ descriptor: CInt, _ action: CInt, _ attributes: UnsafePointer<PosixTermios>) -> CInt {
    unsafe tcsetattr(descriptor, action, attributes)
}

@inline(__always)
func cSetEnvironment(_ name: UnsafePointer<CChar>, _ value: UnsafePointer<CChar>, _ overwrite: CInt) -> CInt {
    unsafe setenv(name, value, overwrite)
}

@inline(__always)
func cSpawn(
    _ process: UnsafeMutablePointer<CInt>,
    _ executable: UnsafePointer<CChar>,
    _ fileActions: UnsafeRawPointer?,
    _ attributes: UnsafeRawPointer?,
    _ arguments: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ environment: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> CInt {
    unsafe posix_spawnp(
        process,
        executable,
        nil,
        nil,
        arguments,
        environment
    )
}

@inline(__always)
func cWait(_ process: CInt, _ status: UnsafeMutablePointer<CInt>, _ options: CInt) -> CInt {
    unsafe waitpid(process, status, options)
}

@inline(__always)
@unsafe func cGetEnvironment() -> UnsafeMutablePointer<UnsafeMutablePointer<CChar>?> {
    guard let pointer = unsafe _NSGetEnviron() else {
        preconditionFailure("_NSGetEnviron returned nil")
    }
    guard let environment = unsafe pointer.pointee else {
        preconditionFailure("_NSGetEnviron returned a nil environment")
    }
    return unsafe environment
}

@inline(__always)
func cErrno() -> UnsafeMutablePointer<CInt> {
    unsafe __error()
}

@inline(__always)
func cExit(_ status: CInt) -> Never {
    exit(status)
}

@inline(__always)
func cKeychainSet(
    _ name: UnsafePointer<CChar>,
    _ value: UnsafeRawPointer?,
    _ length: Int
) -> CInt {
    unsafe vault_keychain_set(
        name,
        value?.assumingMemoryBound(to: UInt8.self),
        length
    )
}

@inline(__always)
func cKeychainGet(
    _ name: UnsafePointer<CChar>,
    _ value: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ length: UnsafeMutablePointer<Int>
) -> CInt {
    unsafe vault_keychain_get(name, value, length)
}

@inline(__always)
func cKeychainDelete(_ name: UnsafePointer<CChar>) -> CInt {
    unsafe vault_keychain_delete(name)
}

@inline(__always)
func cKeychainList(
    _ names: UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?>,
    _ count: UnsafeMutablePointer<Int>
) -> CInt {
    unsafe vault_keychain_list(names, count)
}

@inline(__always)
func cKeychainPurge(_ count: UnsafeMutablePointer<Int>) -> CInt {
    unsafe vault_keychain_purge(count)
}

@inline(__always)
func cKeychainStatusMessage(_ status: CInt) -> UnsafeMutablePointer<CChar>? {
    unsafe vault_keychain_status_message(status)
}

@inline(__always)
func cKeychainFree(_ pointer: UnsafeMutableRawPointer) {
    unsafe vault_keychain_free(pointer)
}
