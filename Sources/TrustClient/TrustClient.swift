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
    var regURL: URL
    var urlSession: URLSession

    var attester: Attester
    var mtls: MTLSIdentity
    var mtlsURLSession: URLSession

    var jose: JOSEIdentity

    public init(regURL: URL, context: String = "default") throws {
        self.regURL = regURL
        let urlSessionCfg = URLSessionConfiguration.ephemeral
        self.urlSession = URLSession(configuration: urlSessionCfg)

        self.attester = Attester(context)
        self.mtls = try MTLSIdentity(context)
        self.mtlsURLSession = try self.mtls.makeURLSession(configuration: urlSessionCfg)

        jose = try JOSEIdentity(context)
    }

    public makeMTLSURLSession(configuration: URLSessionConfiguration = URLSessionConfiguration.ephemeral) throws -> URLSession {
        return try self.mtls.makeURLSession(configuration: configuration)
    }

    func echo() async throws -> EchoOutput {
        let request = URLRequest(url: URL(string: "/echo", relativeTo: self.regURL)!)

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

    func updateMTLSCertificate() async throws -> Certificate {
        let csr = try mtls.createCertificateSigningRequest()
        let csrPEM = try csr.serializeAsPEM()
        print(csrPEM.pemString)
        var request = URLRequest(url: URL(string: "/ca/issue-cert", relativeTo:self.regURL)!)
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
