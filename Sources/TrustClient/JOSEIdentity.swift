import Foundation
import CryptoKit
import SwiftASN1


class JOSEIdentity: SecureEnclaveIdentity {
    var context: String
    var keyTag: String
    var accessFlags: SecAccessControlCreateFlags
    var privateSecKey: SecKey!
    var publicKey: P256.Signing.PublicKey!

    init(
        _ context: String,
        accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
    ) throws {
        self.context = context
        self.keyTag = "tcl:jose:\(context)"
        self.accessFlags = accessFlags
        super.init()
        try prepareKeys()
    }

    private func prepareKeys() throws {
        let existingSecKey = try querySecKey(keyTag)

        if let existingKey = existingSecKey {
            self.privateSecKey = existingKey
        } else {
            print("Cannot load existing identity. Creating new one.")
            self.privateSecKey = try generateSecKey(keyTag, accessFlags: accessFlags)
        }

        self.publicKey = try getPublicKey(privateKey: self.privateSecKey)
    }

}

struct ECKey: Codable {
    var kty: String
    var crv: String
    var x: String
    var y: String
    var kid: String? = nil
    var use: String? = nil
}

extension P256.Signing.PublicKey {

    func jwkRepresentation(kid: String? = nil, use: String? = nil) throws -> Data {
        let size = self.rawRepresentation.count/2

        let x = self.rawRepresentation.prefix(upTo: size)
        let y = self.rawRepresentation.suffix(from: size)

        let jwk = ECKey(
            kty: "EC",
            crv: "P-256",
            x: x.base64URLEncodedString(),
            y: y.base64URLEncodedString(),
            kid: kid,
            use: use
        )

        return try JSONEncoder().encode(jwk)
    }

}
