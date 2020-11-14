import XCTest
import SodiumCrypto
@testable import SodiumCombine


/// Implements the tests for `XchachaPoly`
final class CipherXchachaPolyTests: XCTestCase {
    /// A codable message
    struct Message: Codable, Hashable {
        /// The message kind
        public var kind: Int = Int.random(in: 0...1027)
        /// The payload
        public var payload: Data = try! Random().generate(count: Int.random(in: 0...1024))
    }
    /// A message index
    struct Index: Codable, Hashable {
        /// The message counter
        public var counter: UInt64 = UInt64.random(in: 0...1027)
        /// The context
        public var context: Data = try! Random().generate(count: Int.random(in: 0...1024))
    }
    
    /// Tests successful encryption/decryption of random data
    func testXchachaPoly() throws {
        // Create cipher
        let encoder = JSONEncoder(), decoder = JSONDecoder(),
            key: Data = try Random().generate(count: 32),
            cipher = try CipherXchachaPoly(key: key, encoder: encoder, decoder: decoder)
        
        // Perform some random tests
        for _ in 0...16_384 {
            // Generate random message and index
            let message = Message(), index = Index()
            
            // Encrypt and decrypt message
            let ciphertext = try cipher.encode(message, ad: index),
                plaintext = try cipher.decode(Message.self, from: ciphertext, ad: index)
            XCTAssertEqual(message, plaintext)
        }
    }
    
    /// Tests successful error detection for modified ciphertext
    func testXchachaPolyError() throws {
        // Create cipher
        let encoder = JSONEncoder(), decoder = JSONDecoder(),
            key: Data = try Random().generate(count: 32),
            cipher = try CipherXchachaPoly(key: key, encoder: encoder, decoder: decoder)
        
        // Create a test message and index
        let message = Message(), index = Index(),
            ciphertext = try cipher.encode(message, ad: index)
        
        // Modify the associated data
        do {
            let index = Index(counter: index.counter &+ 1)
            XCTAssertThrowsError(try cipher.decode(Message.self, from: ciphertext, ad: index))
        }
    }
    
    static var allTests = [
        ("testXchachaPoly", testXchachaPoly),
        ("testXchachaPolyError", testXchachaPolyError)
    ]
}
