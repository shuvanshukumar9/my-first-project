package com.example.tools

data class ManifestAuditFinding(
    val severity: Severity,
    val code: String,
    val message: String,
    val guidance: String
)

enum class Severity { LOW, MEDIUM, HIGH }

object AndroidManifestPrivacyAuditor {
    private val exportedPattern = Regex("\\b(android:exported\\s*=\\s*\"true\"|exported\\s*=\\s*true)", RegexOption.IGNORE_CASE)
    private val cleartextPattern = Regex("android:usesCleartextTraffic\\s*=\\s*\"true\"", RegexOption.IGNORE_CASE)
    private val backupPattern = Regex("android:allowBackup\\s*=\\s*\"true\"", RegexOption.IGNORE_CASE)
    private val permissionPattern = Regex("<uses-permission\\b[^>]*android:name\\s*=\\s*\"([^\"]+)\"", RegexOption.IGNORE_CASE)

    fun audit(manifestXml: String): List<ManifestAuditFinding> {
        require(manifestXml.isNotBlank()) { "Manifest XML cannot be blank" }
        val findings = mutableListOf<ManifestAuditFinding>()

        if (cleartextPattern.containsMatchIn(manifestXml)) {
            findings += ManifestAuditFinding(
                Severity.HIGH,
                "CLEARTEXT_TRAFFIC",
                "Cleartext HTTP traffic is explicitly enabled.",
                "Disable usesCleartextTraffic unless a documented legacy requirement exists."
            )
        }

        if (backupPattern.containsMatchIn(manifestXml)) {
            findings += ManifestAuditFinding(
                Severity.MEDIUM,
                "BACKUP_ENABLED",
                "Application backup is explicitly enabled.",
                "Review backup rules and exclude sensitive application data where appropriate."
            )
        }

        if (exportedPattern.containsMatchIn(manifestXml)) {
            findings += ManifestAuditFinding(
                Severity.MEDIUM,
                "EXPORTED_COMPONENT",
                "At least one component is explicitly exported.",
                "Confirm every exported component has a legitimate external-use case and appropriate access controls."
            )
        }

        val permissions = permissionPattern.findAll(manifestXml).map { it.groupValues[1] }.distinct().toList()
        val sensitivePermissions = permissions.filter { permissionRisk(it) >= Severity.MEDIUM.ordinal }
        sensitivePermissions.forEach { permission ->
            val severity = when (permissionRisk(permission)) {
                Severity.HIGH.ordinal -> Severity.HIGH
                else -> Severity.MEDIUM
            }
            findings += ManifestAuditFinding(
                severity,
                "SENSITIVE_PERMISSION",
                "Sensitive permission declared: $permission",
                "Verify the permission is necessary, disclosed to the user, and requested only when needed."
            )
        }

        if (findings.isEmpty()) {
            findings += ManifestAuditFinding(
                Severity.LOW,
                "NO_COMMON_GAPS",
                "No audited privacy/configuration gaps were detected.",
                "Continue reviewing exported components, permissions, backup policy, and network security as the app evolves."
            )
        }
        return findings
    }

    private fun permissionRisk(permission: String): Int = when {
        permission.endsWith("CAMERA") || permission.endsWith("RECORD_AUDIO") -> Severity.HIGH.ordinal
        permission.endsWith("ACCESS_FINE_LOCATION") || permission.endsWith("READ_CONTACTS") ||
            permission.endsWith("READ_SMS") || permission.endsWith("SEND_SMS") -> Severity.HIGH.ordinal
        permission.endsWith("ACCESS_COARSE_LOCATION") || permission.endsWith("POST_NOTIFICATIONS") ||
            permission.endsWith("READ_MEDIA_IMAGES") || permission.endsWith("READ_MEDIA_VIDEO") -> Severity.MEDIUM.ordinal
        else -> Severity.LOW.ordinal
    }
}
