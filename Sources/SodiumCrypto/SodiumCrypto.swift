/// A `SodiumCrypto` related error
public enum SodiumCryptoError: Error {
    /// Some value is not in the expected range
    case rangeViolation(value: Int, expected: Range<Int>, file: String = #file, line: Int = #line)
    /// A cryptographic error occurred (i.e. libsodium returned a non-zero return code)
    case cryptoError(returnCode: Int32, expected: Int32, file: String = #file, line: Int = #line)
}


/// A library return code
internal enum ReturnCode: Int32 {
    /// The ok return code
    case ok = 0
    
    /// Validates that the return code matches `self`
    ///
    ///  - Parameter code: The value to validate
    ///  - Throws: If `code` is not within `self`
    func validate(code: Int32, file: String = #file, line: Int = #line) throws {
        guard self.rawValue == code else {
            throw SodiumCryptoError.cryptoError(returnCode: code, expected: self.rawValue, file: file, line: line)
        }
    }
}
extension ClosedRange where Bound == Int {
    /// Validates that the range contains a given value
    ///
    ///  - Parameter value: The value to validate
    ///  - Throws: If `value` is not within `self`
    func validate(value: Int, file: String = #file, line: Int = #line) throws {
        guard self.contains(value) else {
            throw SodiumCryptoError.rangeViolation(value: value, expected: Range(self), file: file, line: line)
        }
    }
}
