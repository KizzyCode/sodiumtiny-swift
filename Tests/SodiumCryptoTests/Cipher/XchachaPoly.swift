import XCTest
import SodiumMemory
@testable import SodiumCrypto


/// Implements the tests for `XchachaPoly`
final class XchachaPolyTests: XCTestCase {
    /// Tests the implementation against some predefined test vectors
    func testXchachaPolyPredefined() throws {
        /// Define and load the test vectors
        struct TestVector: Codable {
            let key: Data
            let nonce: Data
            let plaintext: Data
            let ad: Data
            let ciphertext: Data
        }
        let testsPath = Bundle.module.url(forResource: "XchachaPoly", withExtension: "json")!,
            testsJSON = try! Data(contentsOf: testsPath),
            tests = try! JSONDecoder().decode([TestVector].self, from: testsJSON)
        
        // Test against test vectors
        for test in tests {
            // Load key and create AEAD instance
            let key = try SecureBytes(copying: test.key), aead = try XchachaPoly(key: key)
            
            // Seal the message
            let ciphertext: Data = try aead.seal(plaintext: test.plaintext, ad: test.ad, nonce: test.nonce)
            XCTAssertEqual(ciphertext, test.ciphertext)
            
            // Reopen the ciphertext
            let plaintext: Data = try aead.open(ciphertext: test.ciphertext, ad: test.ad, nonce: test.nonce)
            XCTAssertEqual(plaintext, test.plaintext)
        }
    }
    
    /// Tests successful encryption/decryption of random data
    func testXchachaPoly() throws {
        // Generate an AEAD instance
        let key = try SecureBytes(random: 32), aead = try XchachaPoly(key: key), rng = Random()
        
        // Perform some random tests
        for _ in 0...16_384 {
            // Generate random message and nonce
            let message: Data = try rng.generate(count: Int.random(in: 0...1027)),
                ad: Data = try rng.generate(count: Int.random(in: 0...1024)),
                nonce: Data = try rng.generate(count: 24)
            
            // Encrypt and decrypt message
            let ciphertext: Data = try aead.seal(plaintext: message, ad: ad, nonce: nonce),
                plaintext: Data = try aead.open(ciphertext: ciphertext, ad: ad, nonce: nonce)
            XCTAssertEqual(message, plaintext)
        }
    }
    
    /// Tests successful error detection for modified ciphertext
    func testXchachaPolyError() throws {
        // Generate an AEAD instance
        let key = try SecureBytes(random: 32), aead = try XchachaPoly(key: key), rng = Random()
        
        // Create a random sealed message
        let plaintext: Data = try rng.generate(count: Int.random(in: 0...1027)),
            ad: Data = try rng.generate(count: Int.random(in: 0...1024)),
            nonce: Data = try rng.generate(count: 24),
            ciphertext: Data = try aead.seal(plaintext: plaintext, ad: ad, nonce: nonce)
        
        // Modify the ciphertext
        do {
            var ciphertext = Data(ciphertext)
            ciphertext[7] = ~ciphertext[7]
            XCTAssertThrowsError(try aead.open(Data.self, ciphertext: ciphertext, ad: ad, nonce: nonce))
        }
        
        // Modify the ciphertext tag
        do {
            var ciphertext = Data(ciphertext)
            ciphertext.append(~ciphertext.popLast()!)
            XCTAssertThrowsError(try aead.open(Data.self, ciphertext: ciphertext, ad: ad, nonce: nonce))
        }
        
        // Modify the associated data
        do {
            var ad = ad.withUnsafeBytes({ Data($0) })
            ad[7] = ~ad[7]
            XCTAssertThrowsError(try aead.open(Data.self, ciphertext: ciphertext, ad: ad, nonce: nonce))
        }
        
        // Modify the nonce
        do {
            var nonce = nonce.withUnsafeBytes({ Data($0) })
            nonce[7] = ~nonce[7]
            XCTAssertThrowsError(try aead.open(Data.self, ciphertext: ciphertext, ad: ad, nonce: nonce))
        }
    }
    
    static var allTests = [
        ("testXchachaPolyPredefined", testXchachaPolyPredefined),
        ("testXchachaPoly", testXchachaPoly),
        ("testXchachaPolyError", testXchachaPolyError)
    ]
}
