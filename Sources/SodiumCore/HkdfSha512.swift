import Foundation
import SodiumMemory
import Clibsodium


/// A HKDF-SHA2-512 implementation
public struct HkdfSha512 {
    /// The valid key size range
    public static let keySize = Int.min ... Int.max
    /// The valid output size range
    public static let outputSize = 0 ... Int(crypto_auth_hmacsha512_BYTES)
    /// The hash algorithm output size
    private static let hashSize = Int(crypto_auth_hmacsha512_BYTES)
    
    /// The base key
    private let baseKey: SecureBytes
    
    /// Creates a new KDF instance
    ///
    ///  - Parameter key: The base key to derive the subkeys from
    public init(baseKey: SecureBytes) throws {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
        
        /// Validate the input
        try Self.keySize.validate(value: baseKey.count)
        self.baseKey = baseKey
    }
    
    /// Derives a subkey
    ///
    ///  - Parameters:
    ///     - salt: A salt to randomize the output if appropriate
    ///     - context: Some context specific parameters; i.e. an app identifier etc.
    ///     - outputCount: The size of the subkey to derive
    public func derive<C: DataProtocol>(salt: ContiguousBytes = [], context: C,
                                        outputCount: Int = 32) throws -> SecureBytes {
        // Validate the input
        try Self.outputSize.validate(value: outputCount)
        
        // Append a `0` byte to the context to mimic the first output block of HKDF
        var paddedContext = try SecureBytes(copying: context)
        try paddedContext.resize(to: paddedContext.count + 1, value: 0x01)
        
        // Prepare the salt and "extract" the key
        let salt: ContiguousBytes = salt.count == 0
            ? [UInt8](repeating: 0, count: Self.hashSize)
            : salt
        let intermediateOutput = try self.hmac(bytes: self.baseKey, key: salt)
        
        // "Expand" the key
        var output = try self.hmac(bytes: paddedContext, key: intermediateOutput)
        try output.resize(to: outputCount)
        return output
    }
    
    /// Computes a HMAC-SHA2-512 over the input
    ///
    ///  - Parameters:
    ///     - bytes: The bytes to authenticate
    ///     - key: The key to authenticate the bytes with
    ///  - Returns: The output bytes
    private func hmac(bytes: ContiguousBytes, key: ContiguousBytes) throws -> SecureBytes {
        // Prepare the vars
        var state = crypto_auth_hmacsha512_state(), output = try SecureBytes(zero: Self.hashSize)
        
        // Authenticate the data
        try bytes.withUnsafeBytes({ bytes, bytesCount in
            try key.withUnsafeBytes({ key, keyCount in
                try output.withUnsafeMutableBytes({ output, _ in
                    // Compute the HMAC
                    try ReturnCode.ok.validate(code: crypto_auth_hmacsha512_init(&state, key, keyCount))
                    try ReturnCode.ok.validate(code: crypto_auth_hmacsha512_update(&state, bytes, UInt64(bytesCount)))
                    try ReturnCode.ok.validate(code: crypto_auth_hmacsha512_final(&state, output))
                })
            })
        })
        return output
    }
}
