package com.example.tools

/** Offline security configuration checklist. It evaluates user-supplied project metadata only. */
object SecurityChecklistTools {
    data class Check(val id: String, val passed: Boolean, val guidance: String)

    fun audit(
        usesHttps: Boolean,
        debugBuild: Boolean,
        secretsInSource: Boolean,
        dependencyLockPresent: Boolean,
        backupsEncrypted: Boolean
    ): List<Check> = listOf(
        Check("https", usesHttps, if (usesHttps) "HTTPS is enabled" else "Use HTTPS for network traffic"),
        Check("debug", !debugBuild, if (!debugBuild) "Debug mode is disabled" else "Disable debug mode for release builds"),
        Check("secrets", !secretsInSource, if (!secretsInSource) "No secrets reported in source" else "Move secrets out of source code"),
        Check("dependencies", dependencyLockPresent, if (dependencyLockPresent) "Dependency lock is present" else "Commit a dependency lockfile"),
        Check("backup-encryption", backupsEncrypted, if (backupsEncrypted) "Backups are encrypted" else "Encrypt backups containing sensitive data")
    )

    fun passedCount(checks: List<Check>): Int = checks.count { it.passed }
}
