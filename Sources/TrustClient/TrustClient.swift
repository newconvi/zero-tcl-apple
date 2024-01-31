import Foundation
import Combine
import CryptoKit
import X509

public enum TrustClientError: Error {
    case genericError(_ details: String = "")
    case invalidRuntimeEnvironent(_ details: String = "")
    case clientNotRegistered
    case badServerResponse(_ statusCode: Int)
    case attestationFailed(cause: Error?)
}

public class TrustClient {
    public var urlSessionConfig: URLSessionConfiguration
    public static var defaultUrlSessionConfig: URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.httpAdditionalHeaders = [
            "User-Agent": "TrustClient/0.0.1"
        ]
        return config
    }
    
    struct Endpoints {
        let baseURL: URL
        let newRegistration: URL
        let echo: URL
        let issueAnonymousCert: URL
        init(baseURL: URL) {
            self.baseURL = baseURL
            self.echo = URL(string: "/echo", relativeTo: baseURL)!
            self.issueAnonymousCert = URL(string: "/ca/issue-cert", relativeTo: baseURL)!
            self.newRegistration = URL(string: "/reg/registrations", relativeTo: baseURL)!
        }
    }
    
    var endpoints: Endpoints
    var urlSession: URLSession

    var attestor: Attestor
    var mtls: MTLSIdentity
    var mtlsURLSession: URLSession

    var jose: JOSEIdentity

    public init(
        regURL: URL,
        context: String = "default",
        urlSessionConfig: URLSessionConfiguration = TrustClient.defaultUrlSessionConfig
    ) throws {
        self.endpoints = Endpoints(baseURL: regURL)
        self.urlSessionConfig = urlSessionConfig
        self.urlSession = URLSession(configuration: urlSessionConfig)

        self.attestor = Attestor(context)
        self.mtls = try MTLSIdentity(context)
        self.mtlsURLSession = try self.mtls.makeURLSession(configuration: urlSessionConfig)

        jose = try JOSEIdentity(context)
    }

    public func makeMTLSURLSession(configuration: URLSessionConfiguration = URLSessionConfiguration.ephemeral) throws -> URLSession {
        return try self.mtls.makeURLSession(configuration: configuration)
    }

    public func echo() async throws -> EchoOutput {
        let request = URLRequest(url: endpoints.echo)

        let (data, response) = try await mtlsURLSession.data(for: request)
        let statusCode = (response as! HTTPURLResponse).statusCode
        if statusCode != 200 {
            throw TrustClientError.badServerResponse(statusCode)
        }
        guard let echoOutput = try? JSONDecoder().decode(EchoOutput.self, from: data) else {
            throw TrustClientError.genericError("Unable to parse JSON to \(EchoOutput.self)")
        }

        return echoOutput
    }
    
    public func updateMTLSCertificate() async throws -> Certificate {
        let csr = try mtls.createCertificateSigningRequest()
        let csrPEM = try csr.serializeAsPEM()
        print(csrPEM.pemString)
        var request = URLRequest(url: endpoints.issueAnonymousCert)
        request.addValue("application/pkcs10", forHTTPHeaderField: "Content-Type")
        request.httpMethod = "POST"
        request.httpBody = Data(csrPEM.derBytes)

        let (data, response) = try await urlSession.data(for: request)
        let statusCode = (response as! HTTPURLResponse).statusCode
        if statusCode != 200 {
            throw TrustClientError.badServerResponse(statusCode)
        }

        guard let pemString = String(data: data, encoding: .utf8) else {
            throw TrustClientError.genericError("Unable to parse server response.")
        }
        let certificate = try Certificate(pemEncoded: pemString)

        try mtls.updateCertificate(certificate)


        return certificate
    }

}
