import Foundation
import CryptoKit
import JOSESwift

// Client registration implementation
public extension TrustClient {
    func register() async throws -> RegistrationOutput {
        var request = URLRequest(url: endpoints.newRegistration)
        request.addValue("application/jose", forHTTPHeaderField: "Content-Type")
        request.httpMethod = "POST"

        let testAttestation = "test attestation".data(using: .utf8)!

        let ephemeralKey = P256.Signing.PrivateKey()
        let prkJwk = try ephemeralKey.jwk()
        let pukJwk = try ephemeralKey.publicKey.jwk()

        var header = try JWSHeader(parameters: [
            "alg": SignatureAlgorithm.ES256.rawValue,
            "urn:gematik:attestation": ["fmt": AttestationFormat.attestation.rawValue, "data": testAttestation.base64EncodedString()]
        ])
        header.jwkTyped = pukJwk
        
        let message = "Summer ⛱, Sun ☀️, Cactus 🌵".data(using: .utf8)!

        let payload = Payload(message)
        
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
        if statusCode != 200 {
            throw TrustClientError.badServerResponse(statusCode)
        }

        guard let output = try? JSONDecoder().decode(RegistrationOutput.self, from: data) else {
            throw TrustClientError.genericError("Unable to parse response")
        }

        return output
    }
}
