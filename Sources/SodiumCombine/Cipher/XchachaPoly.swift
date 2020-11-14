import Foundation
import SodiumCrypto

#if canImport(Combine)
import Combine


/// A `XchachaPoly`-backed cipher implementation
@available(iOS 13, macOS 10.15, macCatalyst 13.0, tvOS 13, watchOS 6.0, *)
public struct CipherXchachaPoly<Encoder: TopLevelEncoder, Decoder: TopLevelDecoder> {
    /// The underlying cipher
    private let cipher: XchachaPoly
    /// The encoder
    private let encoder: Encoder
    /// The decoder
    private let decoder: Decoder
    
    /// Creates a new `XchachaPoly` based cipher instance
    ///
    ///  - Parameters:
    ///     - key: The key to use
    ///     - encoder: The encoder to use
    ///     - decoder: The decoder to use
    public init(key: ContiguousBytes, encoder: Encoder, decoder: Decoder) throws {
        self.cipher = try XchachaPoly(key: key)
        self.encoder = encoder
        self.decoder = decoder
    }
}
@available(iOS 13, macOS 10.15, macCatalyst 13.0, tvOS 13, watchOS 6.0, *)
extension CipherXchachaPoly: CipherTopLevelCoder where Encoder.Output == Data, Decoder.Input == Data {
    public func encode<T: Encodable, A: Encodable>(_ value: T, ad: A?) throws -> Data {
        // Encode and seal plaintext
        let ad = try ad.map({ try self.encoder.encode($0) }) ?? Data(),
            plaintext = try self.encoder.encode(value),
            nonce: Data = try Random().generate(count: 24),
            sealed: Data = try self.cipher.seal(plaintext: plaintext, ad: ad, nonce: nonce)
        
        // Encode the ciphertext
        let ciphertext = Ciphertext(iv: nonce, sealed: sealed)
        return try self.encoder.encode(ciphertext)
    }
    public func decode<T: Decodable, A: Encodable>(_ type: T.Type = T.self, from bytes: Data, ad: A?) throws -> T {
        // Encode and seal plaintext
        let ad = try ad.map({ try self.encoder.encode($0) }) ?? Data(),
            ciphertext = try self.decoder.decode(Ciphertext.self, from: bytes),
            plaintext: Data = try self.cipher.open(ciphertext: ciphertext.sealed, ad: ad, nonce: ciphertext.iv)
        
        // Encode the ciphertext
        return try self.decoder.decode(T.self, from: plaintext)
    }
}
@available(iOS 13, macOS 10.15, macCatalyst 13.0, tvOS 13, watchOS 6.0, *)
extension CipherXchachaPoly: TopLevelEncoder, TopLevelDecoder where Encoder.Output == Data, Decoder.Input == Data {
    public typealias Input = Data
    public typealias Output = Data
    
    /// Encodes and seals a message
    ///
    ///  - Parameter value: The value to encode and seal
    ///  - Returns: The encoded ciphertext bytes
    public func encode<T: Encodable>(_ value: T) throws -> Data {
        try self.encode(value, ad: Data?.none)
    }
    /// Opens a message
    ///
    ///  - Parameters:
    ///     - type: A target type hint
    ///     - bytes: The encoded ciphertext to open
    ///
    ///  - Returns: The opened message
    public func decode<T: Decodable>(_ type: T.Type, from bytes: Data) throws -> T {
        try self.decode(type, from: bytes, ad: Data?.none)
    }
}

#endif
