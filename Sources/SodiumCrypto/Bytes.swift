import Foundation
import Clibsodium


/// A byte object
public protocol Bytes {
    /// Accesses the underlying raw bytes
    ///
    ///  - Parameter body: The accessor for the underlying raw buffer pointer
    ///  - Returns: The result of `body`
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
}
public extension Bytes {
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
extension Data: Bytes {}
extension Array: Bytes where Element == UInt8 {}
extension String: Bytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.data(using: .utf8)!.withUnsafeBytes(body)
    }
}
extension UInt64: Bytes {
    /// Access the underlying bytes in their **big-endian** representation
    ///
    ///  - Parameter body: The accessor for the underlying raw buffer pointer
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Swift.withUnsafeBytes(of: self.bigEndian, body)
    }
}


/// A mutable byte object
public protocol MutableBytes: Bytes {
    /// Accesses the underlying raw bytes
    ///
    ///  - Parameter body: The accessor that gets the pointer and the size of the underlying bytes
    ///  - Returns: The result of the accessor block
    mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R
    
    /// Securely overwrites self with zero bytes
    mutating func erase()
}
public extension MutableBytes {
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
extension Data: MutableBytes {
    public mutating func erase() {
        self.withUnsafeMutableBytes({ sodium_memzero($0.baseAddress!, $0.count) })
    }
}
