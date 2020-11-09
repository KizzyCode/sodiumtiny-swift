import XCTest

import SodiumCoreTests
import SodiumMemoryTests

var tests = [XCTestCaseEntry]()
tests += SodiumCoreTests.__allTests()
tests += SodiumMemoryTests.__allTests()

XCTMain(tests)
