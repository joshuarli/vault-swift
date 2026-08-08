import Testing
@testable import VaultCore

@Test
func parsesLiteralAssignments() {
    #expect(EnvironmentSpecification("PORT=8080") == .literal(name: "PORT", value: "8080"))
    #expect(EnvironmentSpecification("EMPTY=") == .literal(name: "EMPTY", value: ""))
}

@Test
func treatsInvalidLiteralShapesAsKeychainNames() {
    #expect(EnvironmentSpecification("=VALUE") == .keychain(name: "=VALUE"))
    #expect(EnvironmentSpecification("A=B=C") == .keychain(name: "A=B=C"))
    #expect(EnvironmentSpecification("NAME") == .keychain(name: "NAME"))
}

@Test
func stripsOnlyTrailingLineEndings() {
    #expect(stripTrailingLineEndings("secret\n") == "secret")
    #expect(stripTrailingLineEndings("secret\r\n") == "secret")
    #expect(stripTrailingLineEndings("secret\n\n") == "secret\n")
    #expect(stripTrailingLineEndings("secret") == "secret")
}
