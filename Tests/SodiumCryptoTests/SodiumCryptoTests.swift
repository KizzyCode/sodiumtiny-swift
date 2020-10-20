import XCTest
import Sodium
@testable import SodiumCrypto

#if canImport(CryptoKit)
import CryptoKit
#endif

final class SodiumCryptoTests: XCTestCase {
    /// Allocate up to 256 MiB of memory
    func testSecureBytesLargeAlloc() throws {
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
    
    /// Tests the `AeadXchachaPoly` implementation
    func testAeadXchachPoly() throws {
        // Generate an AEAD instance
        let key = try Key(random: 32), aead = try AeadXchachaPoly(key: key), rng = Random()
        
        // Perform some random tests
        for _ in 0 ... 16_384 {
            // Generate random message and nonce
            let message = rng.generate(data: 1027), ad = rng.generate(data: 1024), nonce = rng.generate(data: 24)
            
            // Encrypt and decrypt message
            let ciphertext = try aead.seal(plaintext: message, ad: ad, nonce: nonce),
                plaintext = try aead.open(ciphertext: ciphertext, ad: ad, nonce: nonce)
            XCTAssertEqual(
                message.withUnsafeBytes({ [UInt8]($0) }),
                plaintext.withUnsafeBytes({ [UInt8]($0) }))
        }
    }
    
    /// Tests the `AeadXchachaPoly` implementation against libsodium
    func testAeadXchachPolyCompare() throws {
        // Generate an AEAD instance
        let key = try Key(random: 32), rng = Random(), sodiumKey = key.bytes.withUnsafeBytes({ [UInt8]($0) }),
            aead = try AeadXchachaPoly(key: key), sodiumAead = Sodium().aead.xchacha20poly1305ietf
        
        // Test sealing against libsodium
        for _ in 0 ... 16_384 {
            // Generate a random message and nonce
            let message = rng.generate(data: 1027), nonce = rng.generate(byteArray: 24)
            
            // Seal and split the message
            let ciphertext = try aead.seal(plaintext: message, nonce: nonce),
                sodiumCiphertext = ciphertext.withUnsafeBytes({ [UInt8]($0) })
                
            // Reopen the ciphertext
            let plaintext = sodiumAead.decrypt(authenticatedCipherText: sodiumCiphertext, secretKey: sodiumKey,
                                               nonce: nonce)
            XCTAssertEqual(
                message.withUnsafeBytes({ [UInt8]($0) }),
                plaintext)
        }
    }
    
    /// Tests the `AeadXchachaPoly` implementation
    func testAeadXchachPolyError() throws {
        // Generate an AEAD instance
        let key = try Key(random: 32), aead = try AeadXchachaPoly(key: key), rng = Random()
        
        // Create a random sealed message
        let ad = rng.generate(data: 1024), nonce = rng.generate(data: 24), plaintext = rng.generate(data: 1027),
            ciphertext = try aead.seal(plaintext: plaintext, ad: ad, nonce: nonce)
        
        // Modify the ciphertext
        do {
            var ciphertext = Data(ciphertext)
            ciphertext[7] = ~ciphertext[7]
            XCTAssertThrowsError(try aead.open(ciphertext: ciphertext, ad: ad, nonce: nonce))
        }
        
        // Modify the ciphertext tag
        do {
            var ciphertext = Data(ciphertext)
            ciphertext.append(~ciphertext.popLast()!)
            XCTAssertThrowsError(try aead.open(ciphertext: ciphertext, ad: ad, nonce: nonce))
        }
        
        // Modify the associated data
        do {
            var ad = ad.withUnsafeBytes({ Data($0) })
            ad[7] = ~ad[7]
            XCTAssertThrowsError(try aead.open(ciphertext: ciphertext, ad: ad, nonce: nonce))
        }
        
        // Modify the nonce
        do {
            var nonce = nonce.withUnsafeBytes({ Data($0) })
            nonce[7] = ~nonce[7]
            XCTAssertThrowsError(try aead.open(ciphertext: ciphertext, ad: ad, nonce: nonce))
        }
    }
    
    /// Tests the `KdfBlake2b` implementation against a well known result
    func testHkdfSha512() throws {
        // Setup vars
        let key = try Key(copying: [0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b])
        let salt: [UInt8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c],
            context: [UInt8] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]
        
        // Derive key
        let subkey = try HkdfSha512(baseKey: key).derive(salt: salt, context: context, outputCount: 42)
        let expected: [UInt8] = [0x83, 0x23, 0x90, 0x08, 0x6c, 0xda, 0x71, 0xfb, 0x47, 0x62, 0x5b, 0xb5, 0xce, 0xb1,
                                 0x68, 0xe4, 0xc8, 0xe2, 0x6a, 0x1a, 0x16, 0xed, 0x34, 0xd9, 0xfc, 0x7f, 0xe9, 0x2c,
                                 0x14, 0x81, 0x57, 0x93, 0x38, 0xda, 0x36, 0x2c, 0xb8, 0xd9, 0xf9, 0x25, 0xd7, 0xcb]
        XCTAssertEqual(
            subkey.bytes.withUnsafeBytes({ [UInt8]($0) }),
            expected)
    }
    
    #if canImport(CryptoKit)
    /// Tests the `KdfBlake2b` implementation against CryptoKit
    func testHkdfSha512Compare() throws {
        // Run the code if available or print a warning
        if #available(macOS 11.0, iOS 14.0, macCatalyst 14.0, tvOS 14.0, watchOS 7.0, *) {
            // Generate the random key
            let key = try Key(random: 32), cryptoKitKey = key.bytes.withUnsafeBytes({ SymmetricKey(data: $0) }),
                rng = Random()
            
            // Test against
            for i in 0 ... 16_384 {
                // Generate a random salt and context
                let salt = rng.generate(data: 16_384 - i), context = rng.generate(data: i)
                
                // Compute the subkey using CryptoKit
                let subkey = try HkdfSha512(baseKey: key).derive(salt: salt, context: context, outputCount: 32)
                let cryptoKitSubkey = HKDF<SHA512>.deriveKey(inputKeyMaterial: cryptoKitKey, salt: salt,
                                                             info: context, outputByteCount: 32)
                XCTAssertEqual(
                    subkey.bytes.withUnsafeBytes({ [UInt8]($0) }),
                    cryptoKitSubkey.withUnsafeBytes({ [UInt8]($0) }))
            }
        } else {
            XCTFail("CryptoKit.HDKF is not available")
        }
    }
    #else
    func testKdfBlake2bCompare() throws {
        XCTFail("CryptoKit.HDKF is not available")
    }
    #endif // canImport(CryptoKit)
    
    /// Tests the context combination
    func testHkdfSha512Context() throws {
        // Create a test contexts
        let context = try HkdfSha512.context(fields: "Testolope".data(using: .utf8)!, "Roflor".data(using: .utf8)!)
        let expected: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x54, 0x65, 0x73, 0x74, 0x6F, 0x6C,
                                 0x6F, 0x70, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x52, 0x6F, 0x66,
                                 0x6C, 0x6F, 0x72]
        XCTAssertEqual(context.withUnsafeBytes({ [UInt8]($0) }), expected)
    }
    
    
    /// A rudimentary test the random number generator
    func testRand() {
        // Create the RNG
        let rng = Random()
        
        // Fill buffers with random bytes
        var buffers: [Data] = []
        for _ in 0..<16_384 {
            buffers.append(rng.generate(data: 16_384))
        }
        
        // Deduplicate
        let deduplicated = Set(buffers)
        XCTAssertEqual(deduplicated.count, buffers.count)
    }
    
    static var allTests = [
        ("testSecureBytesLargeAlloc", testSecureBytesLargeAlloc),
        ("testAeadXchachPoly", testAeadXchachPoly),
        ("testAeadXchachPolyCompare", testAeadXchachPolyCompare),
        ("testAeadXchachPolyError", testAeadXchachPolyError),
        ("testHkdfSha512", testHkdfSha512),
        ("testHkdfSha512Compare", testHkdfSha512Compare),
        ("testRand", testRand)
    ]
}
