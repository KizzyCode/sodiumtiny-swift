import XCTest
import SodiumMemory
@testable import SodiumCrypto


/// Implements the tests for `Padding`
final class PaddingTests: XCTestCase {
    /// Tests the implementation against a well known result
    func testPaddingPredefined() throws {
        /// Define and load the test vectors
        struct TestVector: Codable {
            let padded: Data
            let unpadded: Data
        }
        let testsPath = Bundle.module.url(forResource: "Padding", withExtension: "json")!,
            testsJSON = try! Data(contentsOf: testsPath),
            tests = try! JSONDecoder().decode([TestVector].self, from: testsJSON)
        
        // Test against test vectors
        let padding = Padding()
        for test in tests {
            // Pad the data
            let padded: [UInt8] = try padding.applied(bytes: test.unpadded, to: test.padded.count)
            XCTAssertEqual(padded, [UInt8](test.padded))
            
            // Unpad the data
            let unpadded: Data = try padding.removed(bytes: test.padded)
            XCTAssertEqual(unpadded, test.unpadded)
        }
    }
    
    /// Tests successful padding/unpadding of random data
    func testPadding() throws {
        // Generate a padding instance
        let padding = Padding(), rng = Random()
        
        // Perform some random tests
        for _ in 0...16_384 {
            // Generate random message and block size
            let message: Data = try rng.generate(count: Int.random(in: 0...1027)),
                blockSize = Int.random(in: (message.count + 1)...((message.count + 1) * 7))
            
            // Pad and unpad message
            let padded: Data = try padding.applied(bytes: message, to: blockSize),
                unpadded: Data = try padding.removed(bytes: padded)
            XCTAssertEqual(padded.count, blockSize)
            XCTAssertEqual(message, unpadded)
        }
    }
    
    /// Tests successful error detection of invalid ciphertext
    func testPaddingError() throws {
        // Generate a padding instance
        let padding = Padding(), rng = Random()
        
        // Test invalid block sizes
        do {
            let message: Data = try rng.generate(count: Int.random(in: 0...1027))
            XCTAssertThrowsError(try padding.applied(Data.self, bytes: message, to: message.count))
        }
        do {
            let message: Data = try rng.generate(count: Int.random(in: 1...1027))
            XCTAssertThrowsError(try padding.applied(Data.self, bytes: message, to: message.count - 1))
        }
        do {
            let message: Data = try rng.generate(count: Int.random(in: 1...1027))
            XCTAssertThrowsError(try padding.applied(Data.self, bytes: message, to: 0))
        }
        
        // Test invalid padding
        do {
            let invalid = Data([0x80, 0x00, 0x54, 0x65, 0x73, 0x74, 0x6F, 0x6C, 0x6F, 0x70, 0x65])
            XCTAssertThrowsError(try padding.removed(Data.self, bytes: invalid))
        }
    }
}
