import Foundation
import Security

/// The service namespace owned by vault. Accounts are environment variable
/// names and values are stored as generic-password data in the login Keychain.
public struct KeychainStore: Sendable {
    public static let service = "dev.joshuarli.vault"

    private let service: String

    public init(service: String = KeychainStore.service) {
        self.service = service
    }

    public func setSecret(name: String, value: Data) throws {
        try validate(name: name)

        let updateStatus = SecItemUpdate(
            query(service: service, name: name) as CFDictionary,
            [kSecValueData as String: value] as CFDictionary
        )

        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw KeychainError.operation(
                action: "set",
                name: name,
                status: updateStatus
            )
        }

        try create(service: service, name: name, value: value)
    }

    public func secret(named name: String) throws -> String {
        try validate(name: name)

        var dataQuery = query(service: service, name: name)
        dataQuery[kSecReturnData as String] = true
        dataQuery[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = unsafe SecItemCopyMatching(dataQuery as CFDictionary, &result)
        if status == errSecItemNotFound {
            throw KeychainError.notFound(name: name)
        }
        guard status == errSecSuccess else {
            throw KeychainError.operation(
                action: "get",
                name: name,
                status: status
            )
        }

        guard let data = result as? Data else {
            throw KeychainError.missingPasswordData(name: name)
        }

        guard let value = String(data: data, encoding: .utf8) else {
            throw KeychainError.invalidUTF8(name: name)
        }
        return value
    }

    public func deleteSecret(named name: String) throws {
        try validate(name: name)

        let item = try findItem(named: name)
        let deleteStatus = SecKeychainItemDelete(item)
        guard deleteStatus == errSecSuccess else {
            throw KeychainError.operation(
                action: "delete",
                name: name,
                status: deleteStatus
            )
        }
    }

    public func listSecrets() throws -> [String] {
        let attributesQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]

        var result: CFTypeRef?
        let status = unsafe SecItemCopyMatching(attributesQuery as CFDictionary, &result)

        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw KeychainError.operation(
                action: "list",
                name: nil,
                status: status
            )
        }

        guard let result else {
            return []
        }

        let records: [[String: Any]]
        if let multiple = result as? [[String: Any]] {
            records = multiple
        } else if let one = result as? [String: Any] {
            records = [one]
        } else {
            return []
        }

        return records.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }

    @discardableResult
    public func purgeSecrets() throws -> Int {
        let names = try listSecrets()
        for name in names {
            try deleteSecret(named: name)
        }
        return names.count
    }

    private func create(service: String, name: String, value: Data) throws {
        var keychain: SecKeychain?
        let defaultStatus = unsafe SecKeychainCopyDefault(&keychain)
        guard defaultStatus == errSecSuccess, let keychain else {
            throw KeychainError.operation(
                action: "get default Keychain for set",
                name: name,
                status: defaultStatus
            )
        }

        let storage = value.isEmpty ? Data([0]) : value
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

    private func query(service: String, name: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name,
        ]
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

private func statusMessage(_ status: OSStatus) -> String {
    if let message = SecCopyErrorMessageString(status, nil) {
        return "\(message) (OSStatus \(status))"
    }
    return "OSStatus \(status)"
}
