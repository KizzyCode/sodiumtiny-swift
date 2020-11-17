import XCTest
@testable import SodiumTiny


/// Implements the tests for `Blake2b`
final class Blake2bTests: XCTestCase {
    /// Tests against precomputed values
    func testBlake2b() throws {
        // Define the well-known test vectors
        struct WellKnown: Decodable {
            public let bytes: Data
            public let hash: Data
        }
        let wellKnown =
            """
            [
              {
                "bytes": "",
                "hash": "sygRQjN39S14Yihu4acu5UBSQ4D9oXJKbyXXl4xv0yRKbK8EmIEmc8XgXvWDglEA"
              },
              {
                "bytes": "",
                "hash": "eGoC90IBWQPGxv2FJVLScpEvR0DhWEdhiobiF/cfVBnSXhAxr+5YUxOJZESTTrBLkDpoWxRIt1XVb3Aa/pvizg=="
              },
              {
                "bytes": "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==",
                "hash": "qK3Uvd39k+SHfSdG5igXsRY2Sh+nvBSNlQkLxzM7NnP4JAHPeqLkyx7NkCluPxTLVBP47Xe+cwRbE5FM3NapGA=="
              }
            ]
            """
        
        // Create a Blake2b instance and decode test vectors
        let blake2b = Blake2b(),
            tests = try JSONDecoder().decode([WellKnown].self, from: wellKnown.data(using: .utf8)!)
        for test in tests {
            let hash: Data = try blake2b.hash(bytes: test.bytes, count: test.hash.count)
            XCTAssertEqual(hash, test.hash)
        }
    }
    
    static var allTests = [
        ("testBlake2b", testBlake2b)
    ]
}
