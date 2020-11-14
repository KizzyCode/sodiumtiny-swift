import XCTest

import SodiumCombineTests
import SodiumCryptoTests
import SodiumMemoryTests

var tests = [XCTestCaseEntry]()
tests += SodiumCombineTests.__allTests()
tests += SodiumCryptoTests.__allTests()
tests += SodiumMemoryTests.__allTests()

XCTMain(tests)
