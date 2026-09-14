package com.example.tools

/** Offline password-strength heuristic analyzer. Never stores or transmits the password. */
object PasswordStrengthTools {
    data class Result(val score: Int, val rating: String, val feedback: List<String>)

    fun analyze(password: String): Result {
        require(password.isNotEmpty()) { "password must not be empty" }
        var score = 0
        if (password.length >= 8) score++
        if (password.length >= 12) score++
        if (password.length >= 16) score++
        if (password.any(Char::isLowerCase)) score++
        if (password.any(Char::isUpperCase)) score++
        if (password.any(Char::isDigit)) score++
        if (password.any { !it.isLetterOrDigit() }) score++

        val feedback = mutableListOf<String>()
        if (password.length < 12) feedback += "Use at least 12 characters"
        if (!password.any(Char::isLowerCase)) feedback += "Add lowercase letters"
        if (!password.any(Char::isUpperCase)) feedback += "Add uppercase letters"
        if (!password.any(Char::isDigit)) feedback += "Add numbers"
        if (!password.any { !it.isLetterOrDigit() }) feedback += "Add symbols"
        if (password.lowercase() in commonPasswords) feedback += "Avoid common passwords"
        if (hasRepeatedRun(password)) feedback += "Avoid long repeated-character runs"

        val adjusted = (score - if (password.lowercase() in commonPasswords) 3 else 0).coerceIn(0, 7)
        val rating = when (adjusted) { 0, 1 -> "Very weak"; 2, 3 -> "Weak"; 4 -> "Fair"; 5 -> "Strong"; else -> "Very strong" }
        return Result(adjusted, rating, feedback)
    }

    private fun hasRepeatedRun(s: String): Boolean = s.windowed(3).any { it[0] == it[1] && it[1] == it[2] }
    private val commonPasswords = setOf("password", "password123", "12345678", "qwerty", "qwerty123", "admin", "letmein")
}
