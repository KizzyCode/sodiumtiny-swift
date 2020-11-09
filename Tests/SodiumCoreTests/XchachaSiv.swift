import XCTest
import SodiumMemory
@testable import SodiumCore


/// Implements the tests for `XchachaSiv`
final class XchachaSivTests: XCTestCase {
    /// Tests successful encryption/decryption of random data
    func testXchachaSiv() throws {
        // Generate an AEAD instance
        let key = try SecureBytes(random: 32), siv = try XchachaSiv(key: key), rng = Random()
        
        // Perform some random tests
        for _ in 0...16_384 {
            // Generate random message and nonce
            let message = rng.generate(data: Int.random(in: 0...1027)),
                ad = rng.generate(data: Int.random(in: 0...1024)),
                iv = rng.generate(data: 16)
            
            // Encrypt and decrypt message
            let ciphertext = try siv.seal(plaintext: message, ad: ad, iv: iv),
                plaintext = try siv.open(ciphertext: ciphertext, ad: ad, iv: iv)
            XCTAssertEqual(message, Data(plaintext))
        }
    }
    
    /// Tests successful error detection for modified ciphertext
    func testXchachaSivError() throws {
        // Generate an AEAD instance
        let key = try SecureBytes(random: 32), siv = try XchachaSiv(key: key), rng = Random()
        
        // Create a random sealed message
        let plaintext = rng.generate(data: Int.random(in: 0...1027)),
            ad = rng.generate(data: Int.random(in: 0...1024)),
            iv = rng.generate(data: 16),
            ciphertext = try siv.seal(plaintext: plaintext, ad: ad, iv: iv)
        
        // Modify the ciphertext
        do {
            var ciphertext = Data(ciphertext)
            ciphertext[7] = ~ciphertext[7]
            XCTAssertThrowsError(try siv.open(ciphertext: ciphertext, ad: ad, iv: iv))
        }
        
        // Modify the ciphertext tag
        do {
            var ciphertext = Data(ciphertext)
            ciphertext.append(~ciphertext.popLast()!)
            XCTAssertThrowsError(try siv.open(ciphertext: ciphertext, ad: ad, iv: iv))
        }
        
        // Modify the associated data
        do {
            var ad = ad.withUnsafeBytes({ Data($0) })
            ad[7] = ~ad[7]
            XCTAssertThrowsError(try siv.open(ciphertext: ciphertext, ad: ad, iv: iv))
        }
        
        // Modify the nonce
        do {
            var iv = iv.withUnsafeBytes({ Data($0) })
            iv[7] = ~iv[7]
            XCTAssertThrowsError(try siv.open(ciphertext: ciphertext, ad: ad, iv: iv))
        }
    }
    
    static var allTests = [
        ("testXchachaSiv", testXchachaSiv),
        ("testXchachaSivError", testXchachaSivError)
    ]
}
