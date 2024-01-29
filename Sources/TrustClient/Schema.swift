import Foundation

struct EchoOutput: Codable {
    let headers: [String: [String]]
    let host: String
    let metadata: [String: String]
    let method: String
    let proto: String
    let remoteAddr: String
    let requestURI: String
    let tlsCipherSuite: String
    let tlsClientCertificates: [TLSCertificate]
    let tlsHostname: String
    let tlsVersion: String
}

struct TLSCertificate: Codable {
    let issuer: String
    let notAfter: String
    let notBefore: String
    let subject: String
}