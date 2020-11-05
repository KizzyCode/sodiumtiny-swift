import Foundation
import Clibsodium
import XChaChaSIV


/// XChaCha20+Blake2b SIV
public struct XchachaSIV {
    /// The key size
    public static let keySize = Int(crypto_aead_det_xchacha20_KEYBYTES) ... Int(crypto_aead_det_xchacha20_KEYBYTES)
    /// The nonce size
    public static let nonceSize = Int(crypto_aead_det_xchacha20_NONCEBYTES)
        ... Int(crypto_aead_det_xchacha20_NONCEBYTES)
    
    /// The key
    private let key: Key
    
    /// Creates a new AEAD instance
    ///
    ///  - Parameter key: The key to use
    public init(key: Key) throws {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
        
        /// Validate the input
        try Self.keySize.validate(value: key.bytes.count)
        self.key = key
    }
    
    /// Seals a message
    ///
    ///  - Parameters:
    ///     - plaintext: The message to seal
    ///     - ad: The associated data to authenticate
    ///     - nonce: The nonce to use
    ///
    ///  - Returns: The sealed box
    public func seal(plaintext: ContiguousBytes, ad: ContiguousBytes = [], nonce: ContiguousBytes) throws -> Data {
        // Validate input
        try Self.nonceSize.validate(value: nonce.count)
        
        // Prepare vars
        var output = Data(count: plaintext.count + Int(crypto_aead_det_xchacha20_ABYTES))
        
        // Seal the message
        try nonce.withUnsafeBytes({ nonce, _ in
            try plaintext.withUnsafeBytes({ plaintext, plaintextCount in
                try ad.withUnsafeBytes({ ad, adCount in
                    try self.key.bytes.withUnsafeBytes({ key, _ in
                        try output.withUnsafeMutableBytes({ output, _ in
                            // Encrypt the data
                            let result = crypto_aead_det_xchacha20_encrypt(
                                output, plaintext, plaintextCount, ad, adCount,
                                nonce, key)
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
    ///     - ad: The associated data to authenticate
    ///     - nonce: The nonce to use
    ///
    ///  - Returns: The opened message
    public func open(ciphertext: ContiguousBytes, ad: ContiguousBytes = [],
                     nonce: ContiguousBytes) throws -> SecureBytes {
        // Validate input
        try Self.nonceSize.validate(value: nonce.count)
        
        // Prepare vars
        var output = try SecureBytes(zero: ciphertext.count)
        
        // Open the message
        try nonce.withUnsafeBytes({ nonce, _ in
            try ciphertext.withUnsafeBytes({ ciphertext, ciphertextCount in
                try ad.withUnsafeBytes({ ad, adCount in
                    try self.key.bytes.withUnsafeBytes({ key, _ in
                        try output.withUnsafeMutableBytes({ output, _ in
                            // Decrypt the data
                            let result = crypto_aead_det_xchacha20_decrypt(
                                output, ciphertext, ciphertextCount, ad, adCount,
                                nonce, key)
                            try ReturnCode.ok.validate(code: result)
                        })
                    })
                })
            })
        })
        
        // Trim and return output
        try output.resize(to: ciphertext.count - Int(crypto_aead_det_xchacha20_ABYTES))
        return output
    }
}