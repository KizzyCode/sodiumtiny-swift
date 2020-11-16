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
    ///  - Parameters:
    ///     - bytes: The bytes to copy
    ///     - count: The amount of bytes to allocate and copy
    init(copying bytes: ContiguousBytes, count: Int? = nil) throws {
        try self.init(count: count ?? bytes.count)
        
        // Copy the bytes
        let toCopy = min(bytes.count, self.count)
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


/// Some libsodium managed secure memory
public class SecureBytes {
    /// The raw memory
    private(set) public var ptr: UnsafeMutableRawPointer
    /// The memory size
    private(set) public var count: Int
    /// The access retain counter
    private var retains = (ro: 0, rw: 0)
    
    /// Allocates some memory without initializing it
    ///
    ///  - Parameter count: The amount of bytes to allocate
    required public init(count: Int) throws {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
        
        // Allocate the memory
        guard let ptr = sodium_malloc(count) else {
            throw SodiumTinyError.allocationError(count: count)
        }
        sodium_mprotect_noaccess(ptr)
        
        // Set the vars
        self.ptr = ptr
        self.count = count
    }
    deinit {
        sodium_free(self.ptr)
    }
    
    /// Executes the `update`-closure and applies the appropriate protection
    ///
    ///  - Parameter update: A closure that updates the retain counters
    private func setProtection(_ update: @autoclosure () -> Void) {
        // Update the retain counters
        update()
        
        // Apply the appropriate protection levels
        switch self.retains {
            case let (_, rw) where rw > 0: sodium_mprotect_readwrite(self.ptr)
            case let (ro, _) where ro > 0: sodium_mprotect_readonly(self.ptr)
            default: sodium_mprotect_noaccess(self.ptr)
        }
    }
}
extension SecureBytes: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        // Set the appropriate protection
        self.setProtection(self.retains.ro += 1)
        defer { self.setProtection(self.retains.ro -= 1) }
        
        // Access the memory
        let ptr = UnsafeRawBufferPointer(start: self.ptr, count: self.count)
        return try body(ptr)
    }
}
extension SecureBytes: MutableContiguousBytes {
    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        // Set the appropriate protection
        self.setProtection(self.retains.rw += 1)
        defer { self.setProtection(self.retains.rw -= 1) }
        
        // Access the memory
        let ptr = UnsafeMutableRawBufferPointer(start: self.ptr, count: self.count)
        return try body(ptr)
    }
}
