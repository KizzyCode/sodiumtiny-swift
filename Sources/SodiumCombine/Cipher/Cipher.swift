import Foundation

#if canImport(Combine)
import Combine


/// A ciphertext struct
public struct Ciphertext: Codable {
    /// The IV used to seal the bytes
    public let iv: Data
    /// The sealed bytes
    public let sealed: Data
}


/// A cipher-specific extension to `TopLevelEncoder` and `TopLevelDecoder`
@available(iOS 13, macOS 10.15, macCatalyst 13.0, tvOS 13, watchOS 6.0, *)
public protocol CipherTopLevelCoder: TopLevelEncoder, TopLevelDecoder {
    /// The encoder to use to encode the input and the ciphertext
    associatedtype Encoder: TopLevelEncoder
    /// The encoder to use to encode the input and the ciphertext
    associatedtype Decoder: TopLevelDecoder
    
    /// Encodes and seals a message
    ///
    ///  - Parameters:
    ///     - value: The value to encode and seal
    ///     - ad: The associated data to use
    ///
    ///  - Returns: The encoded ciphertext bytes
    func encode<T: Encodable, A: Encodable>(_ value: T, ad: A?) throws -> Data
    /// Opens and decodes a message
    ///
    ///  - Parameters:
    ///     - type: A target type hint
    ///     - bytes: The encoded ciphertext to open
    ///     - ad: The associated data used during encryption
    ///
    ///  - Returns: The opened message
    func decode<T: Decodable, A: Encodable>(_ type: T.Type, from bytes: Data, ad: A?) throws -> T
}


#endif
