package com.example

import com.example.tools.PrivacyAuditTools
import java.nio.file.Files
import java.io.File

fun main() {
    val dir = Files.createTempDirectory("sv-privacy").toFile()
    try {
        File(dir, "notes.txt").writeText("hello world")
        File(dir, ".env").writeText("API_KEY=example")
        val findings = PrivacyAuditTools.audit(dir)
        check(findings.any { it.path == ".env" && it.category == "filename" })
        check(findings.any { it.path == ".env" && it.category == "content" })
        check(PrivacyAuditTools.audit(File(dir, "notes.txt")).isEmpty())
        println("SMOKE_TEST_PASS")
    } finally { dir.deleteRecursively() }
}
