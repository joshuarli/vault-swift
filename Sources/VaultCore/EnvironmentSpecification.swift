/// One environment assignment requested by exec mode.
public enum EnvironmentSpecification: Equatable, Sendable {
    case keychain(name: String)
    case literal(name: String, value: String)

    public init(_ specification: String) {
        if let equals = specification.firstIndex(of: "=") {
            let name = String(specification[..<equals])
            let valueStart = specification.index(after: equals)
            let value = String(specification[valueStart...])
            if !name.isEmpty && !value.contains("=") {
                self = .literal(name: name, value: value)
                return
            }
        }
        self = .keychain(name: specification)
    }
}

public func stripTrailingLineEndings(_ value: String) -> String {
    var scalars = value.unicodeScalars
    if scalars.last?.value == 0x0A {
        scalars.removeLast()
    }
    if scalars.last?.value == 0x0D {
        scalars.removeLast()
    }
    return String(scalars)
}
