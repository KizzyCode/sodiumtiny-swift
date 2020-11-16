import XCTest
@testable import SodiumTiny


/// Implements the tests for `XchachaSiv`
final class XchachaSivTests: XCTestCase {
    /// Tests successful encryption/decryption of random data
    func testXchachaSiv() throws {
        // Perform some random tests
        let rng = Random(), key: SecureBytes = try rng.generate(count: 32), siv = try XchachaSiv(key: key)
        for _ in 0...16_384 {
            // Generate random message and nonce
            let message: Data = try rng.generate(count: Int.random(in: 0...1027)),
                ad: Data = try rng.generate(count: Int.random(in: 0...1024)),
                iv: Data = try rng.generate(count: 16)
            
            // Encrypt and decrypt message
            let ciphertext: Data = try siv.seal(plaintext: message, ad: ad, iv: iv),
                plaintext: Data = try siv.open(ciphertext: ciphertext, ad: ad, iv: iv)
            XCTAssertEqual(message, plaintext)
        }
    }
    
    /// Tests successful error detection for modified ciphertext
    func testXchachaSivError() throws {
        // Generate an AEAD instance
        let rng = Random(), key: SecureBytes = try rng.generate(count: 32), siv = try XchachaSiv(key: key)
        
        // Create a random sealed message
        let plaintext: Data = try rng.generate(count: Int.random(in: 0...1027)),
            ad: Data = try rng.generate(count: Int.random(in: 0...1024)),
            iv: Data = try rng.generate(count: 16),
            ciphertext: Data = try siv.seal(plaintext: plaintext, ad: ad, iv: iv)
        
        // Modify the ciphertext
        do {
            var ciphertext = Data(ciphertext)
            ciphertext[7] = ~ciphertext[7]
            XCTAssertThrowsError(try siv.open(Data.self, ciphertext: ciphertext, ad: ad, iv: iv))
        }
        
        // Modify the ciphertext tag
        do {
            var ciphertext = Data(ciphertext)
            ciphertext.append(~ciphertext.popLast()!)
            XCTAssertThrowsError(try siv.open(Data.self, ciphertext: ciphertext, ad: ad, iv: iv))
        }
        
        // Modify the associated data
        do {
            var ad = ad.withUnsafeBytes({ Data($0) })
            ad[7] = ~ad[7]
            XCTAssertThrowsError(try siv.open(Data.self, ciphertext: ciphertext, ad: ad, iv: iv))
        }
        
        // Modify the nonce
        do {
            var iv = iv.withUnsafeBytes({ Data($0) })
            iv[7] = ~iv[7]
            XCTAssertThrowsError(try siv.open(Data.self, ciphertext: ciphertext, ad: ad, iv: iv))
        }
    }
    
    static var allTests = [
        ("testXchachaSiv", testXchachaSiv),
        ("testXchachaSivError", testXchachaSivError)
    ]
}
