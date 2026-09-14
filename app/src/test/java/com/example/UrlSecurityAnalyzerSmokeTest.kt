package com.example

import com.example.tools.UrlSecurityAnalyzerTools

fun main() {
    val safe = UrlSecurityAnalyzerTools.analyze("https://example.com/login")
    check(safe.scheme == "https")
    check(safe.host == "example.com")
    check(safe.flags.isEmpty())

    val flagged = UrlSecurityAnalyzerTools.analyze("http://user:pass@example.com:8080/a")
    check("unencrypted HTTP" in flagged.flags)
    check("userinfo present" in flagged.flags)
    check("explicit port" in flagged.flags)

    val nonHttp = UrlSecurityAnalyzerTools.analyze("ftp://example.com")
    check("non-http(s) scheme" in nonHttp.flags)

    println("SMOKE_TEST_PASS")
}
