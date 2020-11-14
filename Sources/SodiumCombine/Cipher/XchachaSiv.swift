import Foundation
import SodiumCrypto

#if canImport(Combine)
import Combine


/// A `XchachaSiv`-backed cipher implementation
@available(iOS 13, macOS 10.15, macCatalyst 13.0, tvOS 13, watchOS 6.0, *)
public struct CipherXchachaSiv<Encoder: TopLevelEncoder, Decoder: TopLevelDecoder> {
    /// The underlying cipher
    private let cipher: XchachaSiv
    /// The nonce generator
    private let makeIV: () throws -> Data?
    /// The encoder
    private let encoder: Encoder
    /// The decoder
    private let decoder: Decoder
    
    /// Creates a new `XchachaPoly` based cipher instance
    ///
    ///  - Parameters:
    ///     - key: The key to use
    ///     - zeroNonce: Whether to use a deterministic all-zero nonce instead of a random nonce
    ///     - encoder: The encoder to use
    ///     - decoder: The decoder to use
    public init(key: ContiguousBytes, zeroNonce: Bool = false, encoder: Encoder, decoder: Decoder) throws {
        self.cipher = try XchachaSiv(key: key)
        self.makeIV = zeroNonce ? { nil } : { try Random().generate(count: 16) }
        self.encoder = encoder
        self.decoder = decoder
    }
}
@available(iOS 13, macOS 10.15, macCatalyst 13.0, tvOS 13, watchOS 6.0, *)
extension CipherXchachaSiv: CipherTopLevelCoder where Encoder.Output == Data, Decoder.Input == Data {
    public func encode<T: Encodable, A: Encodable>(_ value: T, ad: A?) throws -> Data {
        // Encode and seal plaintext
        let ad = try ad.map({ try self.encoder.encode($0) }) ?? Data(),
            plaintext = try self.encoder.encode(value),
            iv = try self.makeIV(),
            sealed: Data = try self.cipher.seal(plaintext: plaintext, ad: ad, iv: iv)
        
        // Encode the ciphertext
        let ciphertext = Ciphertext(iv: iv ?? Data(), sealed: sealed)
        return try self.encoder.encode(ciphertext)
    }
    public func decode<T: Decodable, A: Encodable>(_ type: T.Type = T.self, from bytes: Data, ad: A?) throws -> T {
        // Encode and seal plaintext
        let ad = try ad.map({ try self.encoder.encode($0) }) ?? Data(),
            ciphertext = try self.decoder.decode(Ciphertext.self, from: bytes),
            iv = ciphertext.iv.isEmpty ? nil : ciphertext.iv,
            plaintext: Data = try self.cipher.open(ciphertext: ciphertext.sealed, ad: ad, iv: iv)
        
        // Encode the ciphertext
        return try self.decoder.decode(T.self, from: plaintext)
    }
}
@available(iOS 13, macOS 10.15, macCatalyst 13.0, tvOS 13, watchOS 6.0, *)
extension CipherXchachaSiv: TopLevelEncoder, TopLevelDecoder where Encoder.Output == Data, Decoder.Input == Data {
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
