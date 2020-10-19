import Foundation
import Clibsodium


/// A byte object
public protocol SecureContiguousBytes: ContiguousBytes {}
public extension SecureContiguousBytes {
    /// The amount of bytes in `self`
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
extension UnsafeRawBufferPointer: SecureContiguousBytes {}
extension UnsafeMutableRawBufferPointer: SecureContiguousBytes {}
extension Data: SecureContiguousBytes {}
extension Array: SecureContiguousBytes where Element == UInt8 {}
extension String: SecureContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.data(using: .utf8)!.withUnsafeBytes(body)
    }
}
extension UInt64: SecureContiguousBytes {
    /// Access the underlying bytes in their **big-endian** representation
    ///
    ///  - Parameter body: The accessor for the underlying raw buffer pointer
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Swift.withUnsafeBytes(of: self.bigEndian, body)
    }
}


/// A mutable byte object
public protocol MutableSecureContiguousBytes: SecureContiguousBytes {
    /// Accesses the underlying raw bytes
    ///
    ///  - Parameter body: The accessor that gets the pointer and the size of the underlying bytes
    ///  - Returns: The result of the accessor block
    mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R
    
    /// Securely overwrites self with zero bytes
    mutating func erase()
}
public extension MutableSecureContiguousBytes {
    /// Accesses the underlying raw bytes
    ///
    ///  - Parameter body: The accessor that gets the pointer and the size of the underlying bytes
    ///  - Returns: The result of the accessor body
    mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutablePointer<UInt8>, Int) throws -> R) rethrows -> R {
        // Create working copy
        var this = self
        defer { self = this }
        
        // Access bytes
        return try this.withUnsafeMutableBytes({
            let pointer = $0.baseAddress!.bindMemory(to: UInt8.self, capacity: self.count)
            return try body(pointer, $0.count)
        })
    }
}
extension UnsafeMutableRawBufferPointer: MutableSecureContiguousBytes {
    public mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(self)
    }
    public func erase() {
        sodium_memzero(self.baseAddress!, self.count)
    }
}
extension Array: MutableSecureContiguousBytes where Element == UInt8 {
    public mutating func erase() {
        self.withUnsafeMutableBytes({ $0.erase() })
    }
}
extension Data: MutableSecureContiguousBytes {
    public mutating func erase() {
        self.withUnsafeMutableBytes({ $0.erase() })
    }
}
