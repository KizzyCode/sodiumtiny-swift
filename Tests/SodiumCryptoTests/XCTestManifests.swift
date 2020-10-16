import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(SodiumCryptoTests.allTests),
    ]
}
#endif
