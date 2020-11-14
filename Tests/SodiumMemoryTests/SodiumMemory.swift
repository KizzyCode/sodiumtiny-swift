import XCTest
import SodiumCrypto
@testable import SodiumMemory


/// Implements the tests for `SodiumMemory`
final class SodiumMemoryTests: XCTestCase {
    /// Allocate up to 256 MiB of memory
    func testSodiumMemoryLargeAlloc() throws {
        // Allocate the memory and perform some accesses
        for count in stride(from: 64, through: 256, by: 64) {
            // Fill the memory with random bytes
            let memory = try SodiumMemory(count: count * 1024 * 1024)
            memory.write({ Random().generate(into: $0) })
            
            // Compute a sum and validate that it is larger than 0
            let sum = memory.read({ ptr in
                ptr.reduce(UInt64(0), { $0 + UInt64($1) })
            })
            XCTAssert(sum > 0)
        }
    }
    
    static var allTests = [
        ("testSodiumMemoryLargeAlloc", testSodiumMemoryLargeAlloc)
    ]
}
