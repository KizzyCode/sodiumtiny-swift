import Foundation
import Clibsodium


/// Blake2b
public struct Blake2b {
    /// The output size
    public static let outputSize = Int(crypto_generichash_blake2b_BYTES_MIN)...Int(crypto_generichash_blake2b_BYTES_MAX)
    
    /// Creates a new `Blake2b` instance
    public init() {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
    }
    
    /// Computes a hash over the input
    ///
    ///  - Parameters:
    ///     - type: An optional type hint for the return type
    ///     - bytes: The bytes to hash
    ///     - count: The output hash length
    ///
    ///  - Returns: The hash
    public func hash<R: MutableContiguousBytes>(_ type: R.Type = R.self, bytes: ContiguousBytes,
                                                count: Int = Self.outputSize.max()!) throws -> R {
        // Validate input
        try Self.outputSize.validate(value: count)
        
        // Prepare vars
        var output = try R(count: count)
        
        // Seal the message
        try bytes.withUnsafeBytes({ bytes, bytesCount in
            try output.withUnsafeMutableBytes({ output, outputCount in
                // Hash the data
                let result = crypto_generichash_blake2b(output, outputCount, bytes, UInt64(bytesCount), nil, 0)
                try ReturnCode.ok.validate(code: result)
            })
        })
        return output
    }
}
