import Foundation
import Clibsodium


// Adds an UInt8-pointer accessor to `ContiguousBytes`
internal extension ContiguousBytes {
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
extension UnsafeMutableRawBufferPointer: DataProtocol {
    public typealias Regions = CollectionOfOne<UnsafeMutableRawBufferPointer>
    public var regions: CollectionOfOne<UnsafeMutableRawBufferPointer> { CollectionOfOne(self) }
}
extension UInt64: ContiguousBytes, DataProtocol {
    public typealias Regions = CollectionOfOne<UInt64>
    public typealias Element = UInt8
    public typealias Index = Int
    public typealias SubSequence = UInt64
    public typealias Indices = Range<Int>
    public var regions: CollectionOfOne<UInt64> { CollectionOfOne(self) }
    public var startIndex: Int { 0 }
    public var endIndex: Int { self.count }
    
    public subscript(position: Int) -> UInt8 {
        self.withUnsafeBytes({ $0[0] })
    }
    
    // Create an explicit count implementation to avoid conflicts
    /// The number of bytes in the buffer
    public var count: Int { 8 }
    
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
    /// Accesses the underlying raw bytes
    ///
    ///  - Parameter body: The accessor that gets the pointer and the size of the underlying bytes
    ///  - Returns: The result of the accessor block
    mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R
}
public extension MutableContiguousBytes {
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
            let pointer = $0.baseAddress!.bindMemory(to: UInt8.self, capacity: $0.count)
            return try body(pointer, $0.count)
        })
    }
    
    /// Securely overwrite self with zero bytes
    mutating func erase() {
        self.withUnsafeMutableBytes({ this, thisCount in sodium_memzero(this, thisCount) })
    }
}
extension UnsafeMutableRawBufferPointer: MutableContiguousBytes, MutableDataProtocol {
    public init() {
        self = UnsafeMutableRawBufferPointer.allocate(byteCount: 0, alignment: 1)
    }
    
    public mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(self)
    }
}
extension Array: MutableContiguousBytes where Element == UInt8 {}
extension Data: MutableContiguousBytes {}
