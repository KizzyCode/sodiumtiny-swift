import XCTest
import SodiumMemory
@testable import SodiumCore

#if canImport(CryptoKit)
import CryptoKit
#endif


/// Implements the tests for `HkdfSha512`
final class HkdfSha512Tests: XCTestCase {
    /// Tests the implementation against a well known result
    func testHkdfSha512() throws {
        /// Define and load the test vectors
        struct TestVector: Codable {
            let key: Data
            let context: Data
            let salt: Data
            let derived: Data
        }
        let testsPath = Bundle.module.url(forResource: "HkdfSha512", withExtension: "json")!,
            testsJSON = try! Data(contentsOf: testsPath),
            tests = try! JSONDecoder().decode([TestVector].self, from: testsJSON)
        
        // Test against test vectors
        for test in tests {
            // Load key and create HKDF instance
            let key = try SecureBytes(copying: test.key), hkdf = try HkdfSha512(baseKey: key)
            
            // Derive the key
            let derived = try hkdf.derive(salt: test.salt, context: test.context, outputCount: test.derived.count)
            XCTAssertEqual(Data(derived), test.derived)
        }
    }

    #if canImport(CryptoKit)
    /// Tests successful key generation against `CryptoKit`
    func testHkdfSha512Compare() throws {
        // Run the code if available or print a warning
        if #available(macOS 11.0, iOS 14.0, macCatalyst 14.0, tvOS 14.0, watchOS 7.0, *) {
            // Generate the random key
            let key = try SecureBytes(random: 32), cryptoKitKey = SymmetricKey(data: key),
                rng = Random()
            
            // Test against
            for i in 0...16_384 {
                // Generate a random salt and context
                let salt = rng.generate(data: 16_384 - i), context = rng.generate(data: i)
                
                // Compute the subkey using CryptoKit
                let subkey = try HkdfSha512(baseKey: key).derive(salt: salt, context: context, outputCount: 32)
                let cryptoKitSubkey = HKDF<SHA512>.deriveKey(inputKeyMaterial: cryptoKitKey, salt: salt,
                                                             info: context, outputByteCount: 32)
                XCTAssertEqual([UInt8](subkey), cryptoKitSubkey.withUnsafeBytes({ [UInt8]($0) }))
            }
        } else {
            XCTFail("CryptoKit.HDKF is not available")
        }
    }
    #else
    func testHkdfSha512Compare() throws {
        XCTFail("CryptoKit.HDKF is not available")
    }
    #endif // canImport(CryptoKit)
    
    static var allTests = [
        ("testHkdfSha512", testHkdfSha512),
        ("testHkdfSha512Compare", testHkdfSha512Compare)
    ]
}
