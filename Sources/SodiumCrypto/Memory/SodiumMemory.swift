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
