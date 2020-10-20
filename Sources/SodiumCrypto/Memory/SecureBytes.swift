import Foundation
import Clibsodium


/// A securely erasing and access protecting wrapper for some bytes
public struct SecureBytes {
    /// The allocated memory
    internal var memory: SodiumMemory
    
    // Create an explicit count implementation to avoid conflicts
    /// The number of bytes in the buffer
    public var count: Int { self.memory.count }
    
    /// Creates a new all-zero secure memory object
    ///
    ///  - Parameter count: The amount of zero bytes
    public init(zero count: Int = 0) throws {
        self.memory = try SodiumMemory(count: count)
        self.erase()
    }
    /// Generates some secure bytes filled with cryptographically secure random bytes
    ///
    ///  - Parameter count: The amount of random bytes to generate
    public init(random count: Int) throws {
        self.memory = try SodiumMemory(count: count)
        self.memory.write({ Random().generate(into: $0) })
    }
    /// Creates a new secure memory object by copying the passed bytes
    ///
    ///  - Parameter bytes: The bytes to copy
    public init<D: DataProtocol>(copying bytes: D) throws {
        self.memory = try SodiumMemory(count: bytes.count)
        self.memory.write({ $0.copyBytes(from: bytes) })
    }
    /// Creates a new secure memory object by copying and erasing the passed bytes
    ///
    ///  - Parameter bytes: The bytes that will be copied and erased
    public init<D: DataProtocol & MutableContiguousBytes>(erasing bytes: inout D) throws {
        defer { bytes.erase() }
        try self.init(copying: bytes)
    }
    
    /// Resizes self
    ///
    ///  - Parameters:
    ///     - count: The new size
    ///     - value: The value to initialize new elements with if the new size is greater than the current size
    public mutating func resize(to count: Int, value: UInt8 = 0) throws {
        // Allocate and initialize the new buffer
        let new = try SodiumMemory(count: count)
        new.write({ _ = $0.initializeMemory(as: UInt8.self, repeating: value) })
        
        // Copy the old data and update self
        self.memory.read({ old in
            new.write({ _ = old.copyBytes(to: $0, count: Swift.min(old.count, $0.count)) })
        })
        self.memory = new
    }
}
extension SecureBytes: ContiguousBytes, MutableContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.memory.read(body)
    }
    public mutating func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try self.memory.write(body)
    }
}
extension SecureBytes: MutableDataProtocol {
    public init() {
        try! self.init(zero: 0)
    }
    
    public typealias Regions = CollectionOfOne<SecureBytes>
    public typealias SubSequence = SecureBytes
    
    public var regions: CollectionOfOne<SecureBytes> { CollectionOfOne(self) }
    
    public subscript(position: Int) -> UInt8 {
        get { self.withUnsafeBytes({ $0[position] }) }
        set { self.withUnsafeMutableBytes({ $0[position] = newValue }) }
    }
    
    public var startIndex: Int { 0 }
    public var endIndex: Int { self.count }
}
extension SecureBytes: Codable {
    public init(from decoder: Decoder) throws {
        // Decode the data
        var data = try Data(from: decoder)
        defer { data.erase() }
        
        // Allocate the memory
        self.memory = try SodiumMemory(count: data.count)
        self.memory.write({ _ = data.copyBytes(to: $0) })
    }
    public func encode(to encoder: Encoder) throws {
        // Get a copy of the data and encode it
        var data = self.withUnsafeBytes({ Data($0) })
        defer { data.erase() }
        try data.encode(to: encoder)
    }
}


/// A cryptographic key
///
///  - Discussion: This wrapper exists to hide everything that provides implicit access to the secret bytes like e.g.
///    `DataProtocol`, `ContiguousBytes`, `Codable` etc. Those implementations are still available but must be accessed
///    explicitely via the `.bytes`-property.
public struct Key {
    /// The underlying key bytes
    public let bytes: SecureBytes
    
    /// Creates a new key by wrapping the passed bytes
    ///
    ///  - Parameter bytes: The key bytes to wrap
    public init(wrapping bytes: SecureBytes) {
        self.bytes = bytes
    }
    /// Creates a new cryptographically secure random key
    ///
    ///  - Parameter count: The amount of key bytes to generate
    public init(random count: Int = 32) throws {
        self.bytes = try SecureBytes(random: count)
    }
    /// Creates a new key by copying the passed bytes
    ///
    ///  - Parameter bytes: The key bytes to copy
    public init<D: DataProtocol>(copying bytes: D) throws {
        self.bytes = try SecureBytes(copying: bytes)
    }
    /// Creates a new key by copying and erasing the passed bytes
    ///
    ///  - Parameter bytes: The bytes that will be copied and erased
    public init<D: DataProtocol & MutableContiguousBytes>(erasing bytes: inout D) throws {
        self.bytes = try SecureBytes(erasing: &bytes)
    }
}
