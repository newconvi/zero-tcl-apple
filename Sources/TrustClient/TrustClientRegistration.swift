import Foundation
import CryptoKit
import JOSESwift

// Client registration implementation
public extension TrustClient {
    func nonce() async throws -> String {
        var request = URLRequest(url: endpoints.nonce)
        request.httpMethod = "HEAD"
        
        let (data, response) = try await urlSession.data(for: request)
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
    
    func register(nonce: String) async throws -> RegistrationOutput {
        var request = URLRequest(url: endpoints.newRegistration)
        request.httpMethod = "POST"
        request.addValue("application/jose", forHTTPHeaderField: "Content-Type")
        let ephemeralKey = P256.Signing.PrivateKey()
        let prkJwk = try ephemeralKey.jwk()
        let pukJwk = try ephemeralKey.publicKey.jwk()

        // create key attestation
        var thumbprint = try pukJwk.thumbprint()
        var clientData = Data(base64URLEncoded: thumbprint.data(using: .utf8)!)!
        clientData.append(nonce.data(using: .utf8)!)
        let attestation = try await attestor.generateAndAttestKey(clientData: clientData)
        
        var header = try JWSHeader(parameters: [
            "alg": SignatureAlgorithm.ES256.rawValue,
            "nonce": nonce,
            "urn:telematik:attestation": ["fmt": AttestationFormat.attestation.rawValue, "data": attestation.base64URLEncodedString()]
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
        if statusCode != 201 {
            throw TrustClientError.badServerResponse(statusCode)
        }

        guard let output = try? JSONDecoder().decode(RegistrationOutput.self, from: data) else {
            throw TrustClientError.genericError("Unable to parse response")
        }

        return output
    }
}
