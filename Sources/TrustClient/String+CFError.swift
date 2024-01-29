import Foundation

extension String {
    static func errorText(_ error: Unmanaged<CFError>?) -> String {
        if let error = error {
            return error.takeRetainedValue().localizedDescription
        } else {
            return "Unknown error"
        }
    }
}

