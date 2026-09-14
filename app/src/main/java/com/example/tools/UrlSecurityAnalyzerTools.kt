package com.example.tools

import java.net.URI

/** Offline URL safety heuristics. It never makes network requests. */
object UrlSecurityAnalyzerTools {
    data class Result(
        val normalized: String,
        val scheme: String,
        val host: String?,
        val port: Int?,
        val flags: List<String>
    )

    fun analyze(raw: String): Result {
        val input = raw.trim()
        require(input.isNotEmpty()) { "URL must not be empty" }
        val uri = URI(input)
        val scheme = uri.scheme?.lowercase() ?: ""
        val host = uri.host?.lowercase()
        val flags = buildList {
            if (scheme !in setOf("http", "https")) add("non-http(s) scheme")
            if (host == null) add("host unavailable")
            if (uri.userInfo != null) add("userinfo present")
            if (scheme == "http") add("unencrypted HTTP")
            if (host?.startsWith("xn--") == true || host.contains(".xn--")) add("punycode hostname")
            if (uri.port != -1) add("explicit port")
        }
        return Result(uri.normalize().toString(), scheme, host, if (uri.port == -1) null else uri.port, flags)
    }
}
