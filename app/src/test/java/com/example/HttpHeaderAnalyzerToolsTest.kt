package com.example

import com.example.tools.HttpHeaderAnalyzerTools

fun main() {
    val result = HttpHeaderAnalyzerTools.analyze(
        "Content-Security-Policy: default-src 'self'\n" +
            "X-Content-Type-Options: nosniff\n" +
            "Referrer-Policy: strict-origin"
    )
    check("CSP: present" in result)
    check("X-Content-Type-Options: present" in result)
    check("Referrer-Policy: present" in result)
    check("HSTS: missing" in result)
    check("X-Frame-Options: missing" in result)
    check(HttpHeaderAnalyzerTools.analyze("").all { it.endsWith(": missing") })
    println("SMOKE_TEST_PASS")
}
