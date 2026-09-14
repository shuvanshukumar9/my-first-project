package com.example

import com.example.tools.JwtInspectorTools

fun main() {
    val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJleHAiOjE3MDAwMDAwMDB9.signature"
    val result = JwtInspectorTools.inspect(token)
    check(result.headerJson.contains("HS256"))
    check(result.payloadJson.contains("123"))
    check(result.signaturePresent)
    check(result.warnings.any { it.startsWith("expiration claim") })
    try { JwtInspectorTools.inspect("bad.token") ; error("expected rejection") } catch (_: IllegalArgumentException) { }
    println("SMOKE_TEST_PASS")
}
