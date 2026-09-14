package com.example.tools

/** Offline detector for likely secrets in user-provided text. Never transmits or validates secrets. */
object SecretDetectorTools {
    data class Finding(val type: String, val start: Int, val end: Int, val redacted: String)

    private val rules = listOf(
        "AWS access key" to Regex("\\bAKIA[0-9A-Z]{16}\\b"),
        "GitHub token" to Regex("\\bgh[pousr]_[A-Za-z0-9_]{20,255}\\b"),
        "Slack token" to Regex("\\bxox[baprs]-[A-Za-z0-9-]{10,200}\\b"),
        "Private key" to Regex("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "Generic assignment secret" to Regex("(?i)\\b(?:api[_-]?key|secret|password|passwd|token)\\s*[:=]\\s*([^\\s,;]{8,})")
    )

    fun scan(text: String): List<Finding> {
        require(text.isNotEmpty()) { "text must not be empty" }
        return rules.flatMap { (type, regex) ->
            regex.findAll(text).map { match ->
                val start = match.range.first
                val end = match.range.last + 1
                Finding(type, start, end, redact(match.value))
            }.toList()
        }.sortedBy { it.start }
    }

    private fun redact(value: String): String = when {
        value.length <= 8 -> "[REDACTED]"
        else -> value.take(4) + "…" + value.takeLast(2)
    }
}
