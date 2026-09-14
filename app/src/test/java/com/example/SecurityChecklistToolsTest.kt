package com.example

import com.example.tools.SecurityChecklistTools

fun main() {
    val checks = SecurityChecklistTools.audit(
        usesHttps = true,
        debugBuild = false,
        secretsInSource = false,
        dependencyLockPresent = true,
        backupsEncrypted = false
    )
    check(checks.size == 5)
    check(SecurityChecklistTools.passedCount(checks) == 4)
    check(checks.first { it.id == "https" }.passed)
    check(!checks.first { it.id == "backup-encryption" }.passed)
    check(checks.first { it.id == "debug" }.guidance.contains("disabled"))
    println("SMOKE_TEST_PASS")
}
