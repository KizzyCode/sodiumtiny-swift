import Foundation
import Clibsodium


// Extend `ContiguousBytes`
public extension ContiguousBytes {
    /// The number of bytes in the buffer
    var count: Int {
        self.withUnsafeBytes({ $0.count })
    }
    
    /// Accesses the underlying raw bytes
    ///
    ///  - Parameter body: The accessor that gets the pointer and the size of the underlying bytes
    ///  - Returns: The result of the accessor body
    func withUnsafeBytes<R>(_ body: (UnsafePointer<UInt8>, Int) throws -> R) rethrows -> R {
        try self.withUnsafeBytes({
            let pointer = $0.baseAddress!.bindMemory(to: UInt8.self, capacity: $0.count)
            return try body(pointer, $0.count)
        })
    }
}
extension String: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.data(using: .utf8)!.withUnsafeBytes(body)
    }
}
extension UInt64: ContiguousBytes {
    /// Access the underlying bytes in their **big-endian** representation
    ///
    ///  - Parameter body: The accessor for the underlying raw buffer pointer
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Swift.withUnsafeBytes(of: self.bigEndian, body)
    }
}


/// Indicates that the conforming type is a contiguous collection of mutable raw bytes whose underlying storage is
/// directly accessible by `withUnsafeMutableBytes`
public protocol MutableContiguousBytes: ContiguousBytes {
    /// Creates a new all-zero instance of `Self`
    ///
    ///  - Parameter count: The amount of zero bytes to allocate
    init(count: Int) throws
    
    /// Accesses the underlying raw bytes
    ///
    ///  - Parameter body: The accessor that gets the pointer and the size of the underlying bytes
    ///  - Returns: The result of the accessor block
    mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R
}
public extension MutableContiguousBytes {
    /// Creates a new instance of `Self` by copying the passed bytes
    ///
    ///  - Parameter bytes: The bytes to copy
    init(copying bytes: ContiguousBytes) throws {
        try self.init(copying: bytes, count: bytes.count)
    }
    /// Creates a new instance of `Self` by copying the passed bytes
    ///
    ///  - Parameters:
    ///     - bytes: The bytes to copy
    ///     - count: The amount of bytes to allocate
    init(copying bytes: ContiguousBytes, count: Int) throws {
        try self.init(count: count)
        
        // Copy the bytes
        let toCopy = min(bytes.count, count)
        bytes.withUnsafeBytes({ bytes in
            self.withUnsafeMutableBytes({ this in
                _ = bytes.copyBytes(to: this, count: toCopy)
            })
        })
    }
    
    /// Accesses the underlying raw bytes
    ///
    ///  - Parameter body: The accessor that gets the pointer and the size of the underlying bytes
    ///  - Returns: The result of the accessor body
    mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutablePointer<UInt8>, Int) throws -> R) rethrows -> R {
        return try self.withUnsafeMutableBytes({
            let pointer = $0.baseAddress!.bindMemory(to: UInt8.self, capacity: $0.count)
            return try body(pointer, $0.count)
        })
    }
    
    /// Securely overwrite self with zero bytes
    mutating func erase() {
        self.withUnsafeMutableBytes({ this, thisCount in sodium_memzero(this, thisCount) })
    }
}
extension UnsafeMutableRawBufferPointer: MutableContiguousBytes {
    public init(count: Int) {
        self = UnsafeMutableRawBufferPointer.allocate(byteCount: count, alignment: 1)
    }
    public init() {
        self.init(count: 0)
    }
    
    public mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(self)
    }
}
extension Array: MutableContiguousBytes where Element == UInt8 {
    public init(count: Int) {
        self.init(repeating: 0, count: count)
    }
}
extension Data: MutableContiguousBytes {}
