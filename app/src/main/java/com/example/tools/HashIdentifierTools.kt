package com.example.tools

/** Offline heuristic hash-format identifier. Never cracks or verifies hashes. */
object HashIdentifierTools {
    fun identify(value: String): List<String> {
        val s = value.trim()
        require(s.isNotEmpty()) { "hash must not be empty" }
        val hex = s.all { it in "0123456789abcdefABCDEF" }
        return buildList {
            if (hex && s.length == 32) add("MD5")
            if (hex && s.length == 40) add("SHA-1")
            if (hex && s.length == 64) add("SHA-256")
            if (hex && s.length == 96) add("SHA-384")
            if (hex && s.length == 128) add("SHA-512")
            if (s.matches(Regex("^\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}$"))) add("bcrypt")
            if (startsWithPrefix(s, "sha256:")) add("SHA-256 (prefixed)")
            if (startsWithPrefix(s, "sha512:")) add("SHA-512 (prefixed)")
            if (isEmpty()) add("Unknown")
        }
    }

    private fun startsWithPrefix(value: String, prefix: String) = value.startsWith(prefix, ignoreCase = true)
}
