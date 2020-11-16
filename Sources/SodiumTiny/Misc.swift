import Foundation
import Clibsodium


/// A cryptographically secure random number generator
public struct Random {
    /// Intitializes the RNG
    public init() {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
    }
    
    /// Writes some cryptographically secure random bytes to a pointer
    ///
    ///  - Parameter pointer: The pointer to write the bytes to
    public func generate(into pointer: UnsafeMutableRawBufferPointer) {
        randombytes_buf(pointer.baseAddress!, pointer.count)
    }
    /// Writes some cryptographically secure random bytes into a buffer
    ///
    ///  - Parameter buffer: The buffer to write the bytes to
    public func generate<T: MutableContiguousBytes>(into buffer: inout T) {
        buffer.withUnsafeMutableBytes({ self.generate(into: $0) })
    }
    
    /// Generates some data filled with cryptographically secure random bytes
    ///
    ///  - Parameters:
    ///     - type: An optional type hint for the return type
    ///     - count: The amount of random bytes to generate
    public func generate<R: MutableContiguousBytes>(_ type: R.Type = R.self, count: Int) throws -> R {
        var bytes = try R(count: count)
        self.generate(into: &bytes)
        return bytes
    }
}


/// An ISO/IEC 7816-4 padding implementation
public struct ISO7816Padding {
    /// Creates a new padder
    public init() {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
    }
    
    /// Pads the given bytes
    ///
    ///  - Parameters:
    ///     - type: An optional type hint for the return type
    ///     - bytes: The byte to pad
    ///     - count: The target size to pad the bytes to
    ///  - Returns: The padded bytes
    public func applied<R: MutableContiguousBytes>(_ type: R.Type = R.self, bytes: ContiguousBytes,
                                                   to count: Int) throws -> R {
        // Ensure that the data is paddeable
        guard bytes.count < count else {
            throw SodiumTinyError.rangeViolation(value: bytes.count, expected: 0..<count)
        }
        
        // Prepare vars
        var output = try R(copying: bytes, count: count),
            outputCount: Int = output.count
        
        // Pad the data
        try bytes.withUnsafeBytes({ bytes, bytesCount in
            try output.withUnsafeMutableBytes({ output, _ in
                try ReturnCode.ok.validate(code: sodium_pad(&outputCount, output, bytesCount, count, count))
            })
        })
        return output
    }
    /// Removes the padding from the given bytes
    ///
    ///  - Parameters:
    ///     - type: An optional type hint for the return type
    ///     - bytes: The bytes to unpad
    ///  - Returns: The unpadded bytes
    public func removed<R: MutableContiguousBytes>(_ type: R.Type = R.self, bytes: ContiguousBytes) throws -> R {
        // Get the unpadded length
        var outputCount: Int = 0
        try bytes.withUnsafeBytes({ bytes, bytesCount in
            try ReturnCode.ok.validate(code: sodium_unpad(&outputCount, bytes, bytesCount, bytesCount))
        })
        
        // Copy the bytes to the unpadded output
        var output = try R(count: outputCount)
        bytes.withUnsafeBytes({ bytes in
            output.withUnsafeMutableBytes({ output in
                _ = bytes.copyBytes(to: output, count: outputCount)
            })
        })
        return output
    }
}