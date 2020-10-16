import XCTest

import SodiumCryptoTests

var tests = [XCTestCaseEntry]()
tests += SodiumCryptoTests.allTests()
XCTMain(tests)
