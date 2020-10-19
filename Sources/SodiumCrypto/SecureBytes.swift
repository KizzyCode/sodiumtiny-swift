import Foundation
import Clibsodium


/// A protect guard
private class SodiumMemoryGuard {
    /// The sodium memory
    private weak var memory: SodiumMemory?
    /// Whether the access was mutable or not
    private let mutable: Bool
    
    /// Unprotects the memory and creates
    public init(memory: SodiumMemory, mutable: Bool) {
        // Set the vars
        self.memory = memory
        self.mutable = mutable
        
        // Update retain counters and apply protection
        switch self.mutable {
            case true: self.memory?.retains.rw += 1
            case false: self.memory?.retains.ro += 1
        }
        self.apply()
    }
    deinit {
        // Update retain counters and apply protection
        switch self.mutable {
            case true: self.memory?.retains.rw -= 1
            case false: self.memory?.retains.ro -= 1
        }
        self.apply()
    }
    
    /// Retains `self` while `block` is being executed
    ///
    ///  - Parameter block: The block to execute
    ///  - Returns: The result of `block`
    public func retain<R>(_ block: () throws -> R) rethrows -> R {
        return try block()
    }
    
    /// Applies the protection
    private func apply() {
        switch self.memory {
            case .some(let memory) where memory.retains.rw > 0: sodium_mprotect_readwrite(memory.ptr)
            case .some(let memory) where memory.retains.ro > 0: sodium_mprotect_readonly(memory.ptr)
            case .some(let memory): sodium_mprotect_noaccess(memory.ptr)
            default: break
        }
    }
}


/// Some libsodium managed memory
internal class SodiumMemory {
    /// The raw memory
    private(set) public var ptr: UnsafeMutableRawPointer
    /// The memory size
    private(set) public var count: Int
    /// The access retain counter
    internal var retains = (ro: 0, rw: 0)
    
    /// Allocates some memory without initializing it
    ///
    ///  - Parameter count: The amount of bytes to allocate
    public init(count: Int) {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
        
        // Allocate the memory
        guard let ptr = sodium_malloc(count) else {
            fatalError("Failed to allocate protected memory")
        }
        sodium_mprotect_noaccess(ptr)
        
        // Set the vars
        self.ptr = ptr
        self.count = count
    }
    deinit {
        sodium_mprotect_readwrite(self.ptr)
        sodium_memzero(self.ptr, self.count)
        sodium_free(self.ptr)
    }
    
    /// Accesses the memory for reading
    ///
    ///  - Parameter block: The accessor
    ///  - Returns: The result of `block`
    func read<R>(_ block: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try SodiumMemoryGuard(memory: self, mutable: false).retain({
            let ptr = UnsafeRawBufferPointer(start: self.ptr, count: self.count)
            return try block(ptr)
        })
    }
    /// Accesses the memory for writing
    ///
    ///  - Parameter block: The accessor
    ///  - Returns: The result of `block`
    func write<R>(_ block: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try SodiumMemoryGuard(memory: self, mutable: true).retain({
            let ptr = UnsafeMutableRawBufferPointer(start: self.ptr, count: self.count)
            return try block(ptr)
        })
    }
}


/// A securely erasing and access protecting wrapper for some bytes
public class SecureBytes: Codable {
    /// The allocated memory
    internal var memory: SodiumMemory
    
    /// Creates a new all-zero secure memory object
    ///
    ///  - Parameter count: The amount of zero bytes
    public required init(zero count: Int = 0) {
        self.memory = SodiumMemory(count: count)
        self.memory.write({ sodium_memzero($0.baseAddress, $0.count) })
    }
    /// Generates some secure bytes filled with cryptographically secure random bytes
    ///
    ///  - Parameter count: The amount of random bytes to generate
    public required init(random count: Int) {
        self.memory = SodiumMemory(count: count)
        self.memory.write({ Random().generate(into: $0) })
    }
    /// Creates a new secure memory object by copying the passed bytes
    ///
    ///  - Parameter bytes: The bytes to copy
    public required init(copying bytes: Bytes) {
        self.memory = SodiumMemory(count: bytes.count)
        self.memory.write({ memory in
            bytes.withUnsafeBytes({ memory.copyBytes(from: $0) })
        })
    }
    /// Creates a new secure memory object by copying and erasing the passed bytes
    ///
    ///  - Parameter bytes: The bytes that will be copied and erased
    public convenience init<T: MutableBytes>(erasing bytes: inout T) {
        defer { bytes.erase() }
        self.init(copying: bytes)
    }
    
    // MARK: - Codable implementation
    public required init(from decoder: Decoder) throws {
        // Decode the data
        var data = try Data(from: decoder)
        defer { data.erase() }
        
        // Allocate the memory
        self.memory = SodiumMemory(count: data.count)
        self.memory.write({ _ = data.copyBytes(to: $0) })
    }
    public func encode(to encoder: Encoder) throws {
        // Get a copy of the data and encode it
        var data = self.withUnsafeBytes({ Data($0) })
        defer { data.erase() }
        try data.encode(to: encoder)
    }
}
extension SecureBytes: Bytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.memory.read(body)
    }
}


/// A securely erasing and access protecting wrapper for some mutable bytes
public class MutableSecureBytes: SecureBytes {
    /// Resizes `self`
    ///
    ///  - Parameters:
    ///     - count: The new size
    ///     - value: The value to initialize new elements with if the new size is greater than the current size
    public func resize(to count: Int, value: UInt8 = 0) {
        // Allocate and initialize the new buffer
        let new = SodiumMemory(count: count)
        new.write({ _ = $0.initializeMemory(as: UInt8.self, repeating: value) })
        
        // Copy the old data and update self
        self.memory.read({ old in
            new.write({ _ = old.copyBytes(to: $0, count: min(old.count, $0.count)) })
        })
        self.memory = new
    }
}
extension MutableSecureBytes: MutableBytes {
    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try self.memory.write(body)
    }
    public func erase() {
        self.memory.write({ sodium_memzero($0.baseAddress, $0.count) })
    }
}
