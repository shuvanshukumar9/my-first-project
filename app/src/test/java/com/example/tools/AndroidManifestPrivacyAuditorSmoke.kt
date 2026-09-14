package com.example.tools

fun main() {
    val xml = """
        <manifest>
          <uses-permission android:name="android.permission.CAMERA" />
          <application android:usesCleartextTraffic="true" android:allowBackup="true">
            <activity android:exported="true" />
          </application>
        </manifest>
    """.trimIndent()
    val findings = AndroidManifestPrivacyAuditor.audit(xml)
    check(findings.any { it.code == "CLEARTEXT_TRAFFIC" && it.severity == Severity.HIGH })
    check(findings.any { it.code == "BACKUP_ENABLED" && it.severity == Severity.MEDIUM })
    check(findings.any { it.code == "EXPORTED_COMPONENT" && it.severity == Severity.MEDIUM })
    check(findings.any { it.code == "SENSITIVE_PERMISSION" && it.message.contains("CAMERA") })
    val clean = AndroidManifestPrivacyAuditor.audit("<manifest><application /></manifest>")
    check(clean.single().code == "NO_COMMON_GAPS")
    println("SMOKE_TEST_PASS")
}
