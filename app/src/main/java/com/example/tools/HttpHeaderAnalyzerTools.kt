package com.example.tools

/** Offline analyzer for user-provided HTTP response headers. No network access. */
object HttpHeaderAnalyzerTools {
    private val recommended = listOf(
        "strict-transport-security" to "HSTS",
        "content-security-policy" to "CSP",
        "x-content-type-options" to "X-Content-Type-Options",
        "x-frame-options" to "X-Frame-Options",
        "referrer-policy" to "Referrer-Policy",
        "permissions-policy" to "Permissions-Policy"
    )

    fun analyze(rawHeaders: String): List<String> {
        val present = rawHeaders.lineSequence()
            .map { it.substringBefore(':').trim().lowercase() }
            .filter { it.isNotEmpty() }
            .toSet()
        return recommended.map { (key, label) ->
            if (key in present) "$label: present" else "$label: missing"
        }
    }
}
