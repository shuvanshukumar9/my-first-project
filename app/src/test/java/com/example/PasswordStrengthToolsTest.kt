package com.example

import com.example.tools.PasswordStrengthTools

fun main() {
    val strong = PasswordStrengthTools.analyze("Cedar!River92Moon")
    check(strong.rating == "Very strong")
    check(strong.feedback.isEmpty())

    val weak = PasswordStrengthTools.analyze("password")
    check(weak.rating == "Very weak")
    check("Avoid common passwords" in weak.feedback)

    val missing = PasswordStrengthTools.analyze("abcdefghijk")
    check("Add uppercase letters" in missing.feedback)
    check("Add numbers" in missing.feedback)
    check("Add symbols" in missing.feedback)

    try { PasswordStrengthTools.analyze(""); error("expected rejection") } catch (_: IllegalArgumentException) {}
    println("SMOKE_TEST_PASS")
}
