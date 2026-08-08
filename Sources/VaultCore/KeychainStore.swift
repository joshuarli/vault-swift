import CoreFoundation
import Security

/// The service namespace owned by vault. Accounts are environment variable
/// names and values are stored as generic-password data in the login Keychain.
public struct KeychainStore: Sendable {
    public static let service = "dev.joshuarli.vault"

    private let service: String

    public init(service: String = KeychainStore.service) {
        self.service = service
    }

    public func setSecret(name: String, value: [UInt8]) throws {
        try validate(name: name)

        let updateStatus = SecItemUpdate(
            query(service: service, name: name),
            dictionary([(kSecValueData, data(value))])
        )

        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw KeychainError.operation(action: "set", name: name, status: updateStatus)
        }

        try create(service: service, name: name, value: value)
    }

    public func secret(named name: String) throws -> String {
        try validate(name: name)

        let dataQuery = dictionary([
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, string(service)),
            (kSecAttrAccount, string(name)),
            (kSecReturnData, kCFBooleanTrue),
            (kSecMatchLimit, kSecMatchLimitOne),
        ])

        var result: CFTypeRef?
        let status = unsafe SecItemCopyMatching(dataQuery, &result)
        if status == errSecItemNotFound {
            throw KeychainError.notFound(name: name)
        }
        guard status == errSecSuccess else {
            throw KeychainError.operation(action: "get", name: name, status: status)
        }
        guard let result else {
            throw KeychainError.missingPasswordData(name: name)
        }

        let bytes = unsafe bytes(from: unsafeDowncast(result, to: CFData.self))
        guard let value = decodeUTF8(bytes) else {
            throw KeychainError.invalidUTF8(name: name)
        }
        return value
    }

    public func deleteSecret(named name: String) throws {
        try validate(name: name)
        let item = try findItem(named: name)
        let deleteStatus = SecKeychainItemDelete(item)
        guard deleteStatus == errSecSuccess else {
            throw KeychainError.operation(action: "delete", name: name, status: deleteStatus)
        }
    }

    public func listSecrets() throws -> [String] {
        let attributesQuery = dictionary([
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, string(service)),
            (kSecReturnAttributes, kCFBooleanTrue),
            (kSecMatchLimit, kSecMatchLimitAll),
        ])

        var result: CFTypeRef?
        let status = unsafe SecItemCopyMatching(attributesQuery, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw KeychainError.operation(action: "list", name: nil, status: status)
        }
        guard let result else {
            return []
        }

        let array = unsafe unsafeDowncast(result, to: CFArray.self)
        let count = CFArrayGetCount(array)
        var names: [String] = []
        names.reserveCapacity(count)
        for index in 0..<count {
            guard let itemPointer = unsafe CFArrayGetValueAtIndex(array, index) else {
                continue
            }
            let item = unsafe unsafeBitCast(itemPointer, to: CFDictionary.self)
            let accountKey = unsafe Unmanaged.passUnretained(kSecAttrAccount).toOpaque()
            guard let accountPointer = unsafe CFDictionaryGetValue(item, accountKey) else {
                continue
            }
            let account = unsafe unsafeBitCast(accountPointer, to: CFString.self)
            names.append(string(account))
        }
        return names.sorted()
    }

    @discardableResult
    public func purgeSecrets() throws -> Int {
        let names = try listSecrets()
        for name in names {
            try deleteSecret(named: name)
        }
        return names.count
    }

    private func create(service: String, name: String, value: [UInt8]) throws {
        var keychain: SecKeychain?
        let defaultStatus = unsafe SecKeychainCopyDefault(&keychain)
        guard defaultStatus == errSecSuccess, let keychain else {
            throw KeychainError.operation(
                action: "get default Keychain for set",
                name: name,
                status: defaultStatus
            )
        }

        let storage = value.isEmpty ? [UInt8(0)] : value
        let status = unsafe service.withCString { serviceCString in
            unsafe name.withCString { accountCString in
                unsafe storage.withUnsafeBytes { bytes in
                    unsafe SecKeychainAddGenericPassword(
                        keychain,
                        UInt32(service.utf8.count),
                        serviceCString,
                        UInt32(name.utf8.count),
                        accountCString,
                        UInt32(value.count),
                        bytes.baseAddress!,
                        nil
                    )
                }
            }
        }

        guard status == errSecSuccess else {
            throw KeychainError.operation(action: "set", name: name, status: status)
        }
    }

    private func findItem(named name: String) throws -> SecKeychainItem {
        var item: SecKeychainItem?
        let status = unsafe service.withCString { serviceCString in
            unsafe name.withCString { accountCString in
                unsafe SecKeychainFindGenericPassword(
                    nil,
                    UInt32(service.utf8.count),
                    serviceCString,
                    UInt32(name.utf8.count),
                    accountCString,
                    nil,
                    nil,
                    &item
                )
            }
        }

        if status == errSecItemNotFound {
            throw KeychainError.notFound(name: name)
        }
        guard status == errSecSuccess, let item else {
            throw KeychainError.operation(
                action: "find for delete",
                name: name,
                status: status
            )
        }
        return item
    }

    private func query(service: String, name: String) -> CFDictionary {
        dictionary([
            (kSecClass, kSecClassGenericPassword),
            (kSecAttrService, string(service)),
            (kSecAttrAccount, string(name)),
        ])
    }

    private func validate(name: String) throws {
        guard !name.isEmpty else {
            throw KeychainError.emptyName
        }
        guard !name.utf8.contains(0) else {
            throw KeychainError.invalidName(name: name)
        }
        guard name.utf8.count <= Int(UInt32.max) else {
            throw KeychainError.nameTooLong
        }
    }
}

public enum KeychainError: Error, CustomStringConvertible, Sendable {
    case emptyName
    case invalidName(name: String)
    case nameTooLong
    case notFound(name: String)
    case invalidUTF8(name: String)
    case missingPasswordData(name: String)
    case operation(action: String, name: String?, status: OSStatus)

    public var description: String {
        switch self {
        case .emptyName:
            return "vault: empty name not allowed"
        case let .invalidName(name):
            return "vault: invalid name: \(name)"
        case .nameTooLong:
            return "vault: name is too long"
        case let .notFound(name):
            return "vault: \(name): could not be found"
        case let .invalidUTF8(name):
            return "vault: invalid UTF-8 in \(name)"
        case let .missingPasswordData(name):
            return "vault: missing password data for \(name)"
        case let .operation(action, name, status):
            let subject = name.map { "vault: \($0):" } ?? "vault:"
            return "\(subject) \(action) failed: \(statusMessage(status))"
        }
    }
}

private func string(_ value: String) -> CFString {
    unsafe value.withCString {
        unsafe CFStringCreateWithCString(nil, $0, CFStringBuiltInEncodings.UTF8.rawValue)!
    }
}

private func string(_ value: CFString) -> String {
    let length = CFStringGetMaximumSizeForEncoding(
        CFStringGetLength(value),
        CFStringBuiltInEncodings.UTF8.rawValue
    ) + 1
    var buffer = [CChar](repeating: 0, count: length)
    let copied = unsafe buffer.withUnsafeMutableBufferPointer { buffer in
        unsafe CFStringGetCString(value, buffer.baseAddress, buffer.count, CFStringBuiltInEncodings.UTF8.rawValue)
    }
    guard copied else {
        return ""
    }
    let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    return String(decoding: bytes, as: UTF8.self)
}

private func data(_ value: [UInt8]) -> CFData {
    unsafe value.withUnsafeBytes { bytes in
        unsafe CFDataCreate(kCFAllocatorDefault, bytes.baseAddress, value.count)!
    }
}

private func bytes(from value: CFData) -> [UInt8] {
    let count = CFDataGetLength(value)
    guard count > 0 else {
        return []
    }
    var result = [UInt8](repeating: 0, count: count)
    unsafe result.withUnsafeMutableBytes { buffer in
        unsafe CFDataGetBytes(value, CFRange(location: 0, length: count), buffer.baseAddress!.assumingMemoryBound(to: UInt8.self))
    }
    return result
}

private func dictionary(_ values: [(CFString, CFTypeRef)]) -> CFDictionary {
    var keyCallbacks = kCFTypeDictionaryKeyCallBacks
    var valueCallbacks = kCFTypeDictionaryValueCallBacks
    let result = unsafe CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        0,
        &keyCallbacks,
        &valueCallbacks
    )!
    for (key, value) in values {
        unsafe CFDictionarySetValue(
            result,
            Unmanaged.passUnretained(key).toOpaque(),
            Unmanaged.passUnretained(value).toOpaque()
        )
    }
    return result
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

private func statusMessage(_ status: OSStatus) -> String {
    if let message = SecCopyErrorMessageString(status, nil) {
        return "\(string(message)) (OSStatus \(status))"
    }
    return "OSStatus \(status)"
}
