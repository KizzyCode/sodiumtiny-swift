import Foundation
import Clibsodium
import CXchachaSiv


/// XChaCha20+Blake2b SIV
public struct XchachaSiv {
    /// The key size
    public static let keySize = Int(crypto_aead_det_xchacha20_KEYBYTES)...Int(crypto_aead_det_xchacha20_KEYBYTES)
    /// The IV size
    public static let ivSize = Int(crypto_aead_det_xchacha20_NONCEBYTES)...Int(crypto_aead_det_xchacha20_NONCEBYTES)
    
    /// The key
    private let key: ContiguousBytes
    
    /// Creates a new `XchachaSiv` instance
    ///
    ///  - Parameter key: The key to use
    public init(key: ContiguousBytes) throws {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
        
        /// Validate the input
        try Self.keySize.validate(value: key.count)
        self.key = key
    }
    
    /// Seals a message
    ///
    ///  - Parameters:
    ///     - type: An optional type hint for the return type
    ///     - plaintext: The message to seal
    ///     - ad: The associated data to authenticate
    ///     - iv: The IV to use if any
    ///
    ///  - Returns: The sealed box
    public func seal<R: MutableContiguousBytes>(_ type: R.Type = R.self, plaintext: ContiguousBytes,
                                                ad: ContiguousBytes = [], iv: ContiguousBytes?) throws -> R {
        // Validate input
        let iv: ContiguousBytes = iv ?? Data(count: Self.ivSize.first!)
        try Self.ivSize.validate(value: iv.count)
        
        // Prepare vars
        var output = try R(count: plaintext.count + Int(crypto_aead_det_xchacha20_ABYTES))
        
        // Seal the message
        try iv.withUnsafeBytes({ iv, _ in
            try plaintext.withUnsafeBytes({ plaintext, plaintextCount in
                try ad.withUnsafeBytes({ ad, adCount in
                    try self.key.withUnsafeBytes({ key, _ in
                        try output.withUnsafeMutableBytes({ output, _ in
                            // Encrypt the data
                            let result = crypto_aead_det_xchacha20_encrypt(
                                output, plaintext, plaintextCount, ad, adCount,
                                iv, key)
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
    ///     - type: An optional type hint for the return type
    ///     - ciphertext: The message to open
    ///     - ad: The associated data to authenticate
    ///     - nonce: The nonce to use
    ///
    ///  - Returns: The opened message
    public func open<R: MutableContiguousBytes>(_ type: R.Type = R.self, ciphertext: ContiguousBytes,
                                                ad: ContiguousBytes = [], iv: ContiguousBytes?) throws -> R {
        // Validate input
        let iv: ContiguousBytes = iv ?? Data(count: Self.ivSize.first!)
        try Self.ivSize.validate(value: iv.count)
        
        // Prepare vars
        var output = try R(count: ciphertext.count)
        
        // Open the message
        try iv.withUnsafeBytes({ iv, _ in
            try ciphertext.withUnsafeBytes({ ciphertext, ciphertextCount in
                try ad.withUnsafeBytes({ ad, adCount in
                    try self.key.withUnsafeBytes({ key, _ in
                        try output.withUnsafeMutableBytes({ output, _ in
                            // Decrypt the data
                            let result = crypto_aead_det_xchacha20_decrypt(
                                output, ciphertext, ciphertextCount, ad, adCount,
                                iv, key)
                            try ReturnCode.ok.validate(code: result)
                        })
                    })
                })
            })
        })
        
        // Trim and return output
        output = try R(copying: output, count: ciphertext.count - Int(crypto_aead_det_xchacha20_ABYTES))
        return output
    }
}
