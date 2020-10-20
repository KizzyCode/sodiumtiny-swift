import Foundation
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
    private let baseKey: Key
    
    /// Creates a new KDF instance
    ///
    ///  - Parameter key: The base key to derive the subkeys from
    public init(baseKey: Key) throws {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
        
        /// Validate the input
        try Self.keySize.validate(value: baseKey.bytes.count)
        
        self.baseKey = baseKey
    }
    
    /// Derives a subkey
    ///
    ///  - Parameters:
    ///     - salt: A salt to randomize the output if appropriate
    ///     - context: Some context specific parameters; i.e. an app identifier etc.
    ///     - outputCount: The size of the subkey to derive
    public func derive<C: DataProtocol>(salt: ContiguousBytes = [], context: C,
                                        outputCount: Int = 32) throws -> Key {
        // Validate the input
        try Self.outputSize.validate(value: outputCount)
        
        // Append a `0` byte to the context to mimic the first output block of HKDF
        var paddedContext = try SecureBytes(copying: context)
        try paddedContext.resize(to: paddedContext.count + 1, value: 0x01)
        
        // Prepare the salt and "extract" the key
        let salt: ContiguousBytes = salt.count == 0
            ? [UInt8](repeating: 0, count: Self.hashSize)
            : salt
        let intermediateOutput = try self.hmac(bytes: self.baseKey.bytes, key: salt)
        
        // "Expand" the key
        var output = try self.hmac(bytes: paddedContext, key: intermediateOutput)
        try output.resize(to: outputCount)
        return Key(wrapping: output)
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
    
    /// Builds a context from multiple fields/parameters
    ///
    ///  - Parameter fields: The fields to combine to a single context literal
    ///  - Returns: The new context
    ///
    ///  - Discussion: The context is created by concatenating a field's length followed by the field itself; i.e.:
    ///    `fields[0].count || fields[0] || ... || fields[n].count || fields[n]`, where `.count` is encoded as 64 bit
    ///    big endian integer.
    public static func context(fields: ContiguousBytes...) throws -> SecureBytes {
        // Map the fields to a sequence of `fieldCount, field, ...`
        let fields = fields.flatMap({ [UInt64($0.count), $0] }),
            fieldsCount = fields.reduce(0, { $0 + $1.count })
        
        // Write the fields to the context
        var context = try SecureBytes(zero: fieldsCount), contextPosition = 0
        for field in fields {
            // Write the field
            field.withUnsafeBytes({ field, fieldCount in
                context.withUnsafeMutableBytes({ context in
                    // Write the field and increment the position
                    (context.baseAddress! + contextPosition).copyMemory(from: field, byteCount: fieldCount)
                    contextPosition += fieldCount
                })
            })
        }
        return context
    }
}
