import Foundation
import Combine
import CryptoKit
import X509
import JOSESwift
import SwiftASN1

public enum TrustClientError: Error {
    case genericError(_ details: String = "")
    case invalidRuntimeEnvironent(_ details: String = "")
    case clientNotRegistered
    case badServerResponse(_ statusCode: Int)
    case attestationFailed(cause: Error?)
}

public class TrustClient {
    var _state: State
    public var state: State {
        return _state
    }
    public var urlSessionConfig: URLSessionConfiguration
    public static var defaultUrlSessionConfig: URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.httpAdditionalHeaders = [
            "User-Agent": "TrustClient/0.0.1"
        ]
        return config
    }

    public enum State {
        case unregistered
        case registrationPending
        case registrationError
        case registrationExpired
        case registered
    }

    struct Endpoints {
        let baseURL: URL
        let nonce: URL
        let newRegistration: URL
        // debugging
        let echo: URL
        let issueAnonymousCert: URL
        init(baseURL: URL) {
            self.baseURL = baseURL
            self.nonce = URL(string: "/reg/nonce", relativeTo: baseURL)!
            self.newRegistration = URL(string: "/reg/registrations", relativeTo: baseURL)!
            // debugging
            self.echo = URL(string: "/echo", relativeTo: baseURL)!
            self.issueAnonymousCert = URL(string: "/ca/issue-cert", relativeTo: baseURL)!
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

        if let cert = try mtls.retrieveCertificate() {
            if cert.notValidAfter <= Date() {
                self._state = .registrationExpired
            } else {
                self._state = .registered
            }
        } else {
            self._state = .unregistered
        }
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

    public func nonce() async throws -> String {
        var request = URLRequest(url: endpoints.nonce)
        request.httpMethod = "HEAD"

        let (_, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw TrustClientError.genericError("Where did HTTP go?")
        }
        if httpResponse.statusCode != 201 {
            throw TrustClientError.badServerResponse(httpResponse.statusCode)
        }

        guard let nonce = httpResponse.value(forHTTPHeaderField: "Replay-Nonce") else {
            throw TrustClientError.genericError("Header Replay-Nonce is noct set")
        }

        return nonce
    }

    public func register(nonce: String) async throws -> RegistrationOutput {
        var request = URLRequest(url: endpoints.newRegistration)
        request.httpMethod = "POST"
        request.addValue("application/jose", forHTTPHeaderField: "Content-Type")
        let ephemeralKey = P256.Signing.PrivateKey()
        let prkJwk = try ephemeralKey.jwk()
        let pukJwk = try ephemeralKey.publicKey.jwk()

        // create key attestation
        let thumbprint = try pukJwk.thumbprint()
        var clientData = Data(base64URLEncoded: thumbprint.data(using: .utf8)!)!
        clientData.append(nonce.data(using: .utf8)!)
        let attestation = try await attestor.generateAndAttestKey(clientData: clientData)

        var header = try JWSHeader(parameters: [
            "alg": SignatureAlgorithm.ES256.rawValue,
            "nonce": nonce,
            "urn:telematik:attestation": ["fmt": AttestationFormat.attestation.rawValue, "data": attestation.base64URLEncodedString()]
        ])
        header.jwkTyped = pukJwk

        let csr = try mtls.createCertificateSigningRequest()
        var der = DER.Serializer()
        try csr.serialize(into: &der)

        let registrationInput = RegistrationInput(name: "iPhone", csr: Data(der.serializedBytes).base64EncodedString())

        let payload = Payload(try JSONEncoder().encode(registrationInput))

        let prkSekKey = try prkJwk.secKey()

        guard let signer = Signer(signingAlgorithm: .ES256, key: prkSekKey) else {
            throw TrustClientError.genericError("Unable create JWS signer")
        }

        guard let jws = try? JWS(header: header, payload: payload, signer: signer) else {
            throw TrustClientError.genericError("Unable to sign message using JWS")
        }

        request.httpBody = jws.compactSerializedData

        let (data, response) = try await urlSession.data(for: request)
        let statusCode = (response as! HTTPURLResponse).statusCode
        if statusCode != 201 {
            throw TrustClientError.badServerResponse(statusCode)
        }

        do {
            let output = try JSONDecoder().decode(RegistrationOutput.self, from: data)
            let certificate = try Certificate(derEncoded: output.client.certificate.slice)
            try mtls.updateCertificate(certificate)
            return output
        } catch {
            throw TrustClientError.genericError("Unable to parse response: \(error.localizedDescription)")
        }

    }
}

