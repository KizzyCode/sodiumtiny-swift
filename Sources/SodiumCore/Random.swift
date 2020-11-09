import Foundation
import SodiumMemory
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
    ///  - Parameter count: The amount of random bytes to generate
    public func generate(data count: Int) -> Data {
        var data = Data(count: count)
        self.generate(into: &data)
        return data
    }
    /// Generates a byte array filled with cryptographically secure random bytes
    ///
    ///  - Parameter count: The amount of random bytes to generate
    public func generate(byteArray count: Int) -> [UInt8] {
        var array = [UInt8](repeating: 0, count: count)
        self.generate(into: &array)
        return array
    }
    /// Generates some secure bytes filled with cryptographically secure random bytes
    ///
    ///  - Parameter count: The amount of random bytes to generate
    ///  - Returns: The cryptographically secure random bytes
    public func generate(bytes count: Int) throws -> SecureBytes {
        try SecureBytes(random: count)
    }
}
