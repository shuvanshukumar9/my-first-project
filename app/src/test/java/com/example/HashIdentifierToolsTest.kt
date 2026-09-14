package com.example

import com.example.tools.HashIdentifierTools

fun main() {
    check(HashIdentifierTools.identify("d41d8cd98f00b204e9800998ecf8427e").contains("MD5"))
    check(HashIdentifierTools.identify("a".repeat(40)).contains("SHA-1"))
    check(HashIdentifierTools.identify("a".repeat(64)).contains("SHA-256"))
    check(HashIdentifierTools.identify("$2b$12$" + "a".repeat(53)).contains("bcrypt"))
    check(HashIdentifierTools.identify("not-a-hash").contains("Unknown"))
    check(HashIdentifierTools.identify("").let { false })
    println("SMOKE_TEST_PASS")
}
