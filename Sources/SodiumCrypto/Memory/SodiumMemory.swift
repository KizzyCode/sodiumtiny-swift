import Clibsodium


/// Some libsodium managed memory
internal class SodiumMemory {
    /// The raw memory
    private(set) public var ptr: UnsafeMutableRawPointer
    /// The memory size
    private(set) public var count: Int
    /// The access retain counter
    private var retains = (ro: 0, rw: 0)
    
    /// Allocates some memory without initializing it
    ///
    ///  - Parameter count: The amount of bytes to allocate
    public init(count: Int) throws {
        precondition(sodium_init() >= 0, "Failed to initialize libsodium")
        
        // Allocate the memory
        guard let ptr = sodium_malloc(count) else {
            throw SodiumCryptoError.allocationError(count: count)
        }
        sodium_mprotect_noaccess(ptr)
        
        // Set the vars
        self.ptr = ptr
        self.count = count
    }
    deinit {
        sodium_free(self.ptr)
    }
    
    /// Accesses the memory for reading
    ///
    ///  - Parameter block: The accessor
    ///  - Returns: The result of `block`
    public func read<R>(_ block: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        // Set the appropriate protection
        self.setProtection(self.retains.ro += 1)
        defer { self.setProtection(self.retains.ro -= 1) }
        
        // Access the memory
        let ptr = UnsafeRawBufferPointer(start: self.ptr, count: self.count)
        return try block(ptr)
    }
    /// Accesses the memory for writing
    ///
    ///  - Parameter block: The accessor
    ///  - Returns: The result of `block`
    public func write<R>(_ block: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        // Set the appropriate protection
        self.setProtection(self.retains.rw += 1)
        defer { self.setProtection(self.retains.rw -= 1) }
        
        // Access the memory
        let ptr = UnsafeMutableRawBufferPointer(start: self.ptr, count: self.count)
        return try block(ptr)
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
