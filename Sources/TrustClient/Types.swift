import Foundation

public struct RegistrationInput: Encodable {
    public let name: String
    public let csr: String?
}

public enum RegistrationStatus: String, Codable {
    case pending = "pending"
    case error = "error"
    case cancelled = "cancelled"
    case complete = "complete"
}

public struct RegistrationOutput: Decodable {
    public let id: String
    public let status: RegistrationStatus
    public let client: ClientRegistrationOutput

}

public struct ClientRegistrationOutput: Decodable {
    public let id: String
    public let certificate: Data
}

public struct RegisteredClientOutput: Decodable {
    public let id: String
}

public struct EchoOutput: Decodable {
    public let headers: [String: [String]]
    public let host: String
    public let metadata: [String: String]
    public let method: String
    public let proto: String
    public let remoteAddr: String
    public let requestURI: String
    public let tlsCipherSuite: String
    public let tlsClientCertificates: [TLSCertificate]
    public let tlsHostname: String
    public let tlsVersion: String
}

public struct TLSCertificate: Codable {
    public let issuer: String
    public let notAfter: String
    public let notBefore: String
    public let subject: String
}

enum AttestationFormat: String, Codable {
    case attestation = "apple-attestation"
    case assertion = "apple-assertion"
}
