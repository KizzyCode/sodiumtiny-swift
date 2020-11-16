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
