import Foundation
import Clibsodium


/// An AEAD cipher
public struct AeadXchachaPoly {
    /// The key size
    public static let keySize = Int(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
        ... Int(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    /// The nonce size
    public static let nonceSize = Int(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
        ... Int(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    
    /// The box key
    private let key: SecureBytes
    
    /// Creates a new AEAD instance
    ///
    ///  - Parameter key: The key to use
    public init(key: SecureBytes) throws {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
        
        /// Validate the input
        try Self.keySize.validate(value: key.count)
        
        self.key = key
    }
    
    /// Seals a message
    ///
    ///  - Parameters:
    ///     - plaintext: The message to seal
    ///     - nonce: The nonce to use
    ///
    ///  - Returns: The sealed box
    public func seal(plaintext: Bytes, ad: Bytes = "", nonce: Bytes) throws -> Data {
        // Validate input
        try Self.nonceSize.validate(value: nonce.count)
        
        // Prepare vars
        var output = Data(count: plaintext.count + Int(crypto_aead_xchacha20poly1305_IETF_ABYTES))
        var outputCount: UInt64 = 0
        
        // Seal the message
        try self.key.withUnsafeBytes({ key, _ in
            try nonce.withUnsafeBytes({ nonce, _ in
                try plaintext.withUnsafeBytes({ plaintext, plaintextCount in
                    try ad.withUnsafeBytes({ ad, adCount in
                        try output.withUnsafeMutableBytes({ output, _ in
                            let result = crypto_aead_xchacha20poly1305_ietf_encrypt(output, &outputCount,
                                                                                    plaintext, UInt64(plaintextCount),
                                                                                    ad, UInt64(adCount),
                                                                                    nil, nonce, key)
                            try ReturnCode.ok.validate(code: result)
                        })
                    })
                })
            })
        })
        return output
    }
    
    /// Opens a message
    ///
    ///  - Parameters:
    ///     - ciphertext: The message to open
    ///     - nonce: The nonce to use
    ///
    ///  - Returns: The opened message
    public func open(ciphertext: Bytes, ad: Bytes = "", nonce: Bytes) throws -> SecureBytes {
        // Validate input
        try Self.nonceSize.validate(value: nonce.count)
        
        // Prepare vars
        var output = MutableSecureBytes(zero: ciphertext.count)
        var outputCount: UInt64 = 0
        
        // Open the message
        try self.key.withUnsafeBytes({ key, _ in
            try nonce.withUnsafeBytes({ nonce, _ in
                try ciphertext.withUnsafeBytes({ ciphertext, ciphertextCount in
                    try ad.withUnsafeBytes({ ad, adCount in
                        try output.withUnsafeMutableBytes({ output, _ in
                            let result = crypto_aead_xchacha20poly1305_ietf_decrypt(output, &outputCount, nil,
                                                                                    ciphertext, UInt64(ciphertextCount),
                                                                                    ad, UInt64(adCount), nonce, key)
                            try ReturnCode.ok.validate(code: result)
                        })
                    })
                })
            })
        })
        
        // Trim and return output
        output.resize(to: Int(exactly: outputCount)!)
        return output
    }
}
