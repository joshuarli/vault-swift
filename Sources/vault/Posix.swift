// These declarations keep the executable on the Darwin C ABI without
// importing the Swift Darwin overlay. The overlay adds compatibility dylibs
// to the final load commands; vault only needs this small POSIX slice.

typealias CInt = Int32

struct PosixTermios {
    var c_iflag: UInt64 = 0
    var c_oflag: UInt64 = 0
    var c_cflag: UInt64 = 0
    var c_lflag: UInt64 = 0
    var c_cc: (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    var c_ispeed: UInt64 = 0
    var c_ospeed: UInt64 = 0
}

enum Posix {
    static var echo: UInt64 { 0x00000008 }
    static var echoNewline: UInt64 { 0x00000010 }
    static var canonical: UInt64 { 0x00000100 }
    static var terminalNow: CInt { 0 }
    static var interrupted: CInt { 4 }
}

@_silgen_name("read")
@unsafe func cRead(_ descriptor: CInt, _ buffer: UnsafeMutableRawPointer?, _ count: Int) -> Int

@_silgen_name("write")
@unsafe func cWrite(_ descriptor: CInt, _ buffer: UnsafeRawPointer?, _ count: Int) -> Int

@_silgen_name("isatty")
@unsafe func cIsATTY(_ descriptor: CInt) -> CInt

@_silgen_name("tcgetattr")
@unsafe func cTCGetAttributes(_ descriptor: CInt, _ attributes: UnsafeMutablePointer<PosixTermios>) -> CInt

@_silgen_name("tcsetattr")
@unsafe func cTCSetAttributes(_ descriptor: CInt, _ action: CInt, _ attributes: UnsafePointer<PosixTermios>) -> CInt

@_silgen_name("setenv")
@unsafe func cSetEnvironment(_ name: UnsafePointer<CChar>, _ value: UnsafePointer<CChar>, _ overwrite: CInt) -> CInt

@_silgen_name("strdup")
@unsafe func cDuplicate(_ string: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("posix_spawnp")
@unsafe func cSpawn(
    _ process: UnsafeMutablePointer<CInt>,
    _ executable: UnsafePointer<CChar>,
    _ fileActions: UnsafeRawPointer?,
    _ attributes: UnsafeRawPointer?,
    _ arguments: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ environment: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> CInt

@_silgen_name("waitpid")
@unsafe func cWait(_ process: CInt, _ status: UnsafeMutablePointer<CInt>, _ options: CInt) -> CInt

@_silgen_name("_NSGetEnviron")
@unsafe func cGetEnvironment() -> UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?>?

@_silgen_name("__error")
@unsafe func cErrno() -> UnsafeMutablePointer<CInt>

@_silgen_name("exit")
@unsafe func cExit(_ status: CInt) -> Never
