package com.example.tools

import java.io.File

/** Offline local-file privacy audit. Reports metadata and risky filename/content indicators only. */
object PrivacyAuditTools {
    data class Finding(val path: String, val category: String, val detail: String)

    private val sensitiveName = Regex("(?i)(password|passwd|secret|token|apikey|api_key|private[_-]?key|\\.env$|credentials?)")
    private val sensitiveContent = Regex("(?i)(api[_-]?key|secret|password|authorization:\\s*bearer|private key)")

    fun audit(root: File, maxFiles: Int = 5000): List<Finding> {
        require(root.exists()) { "path does not exist" }
        require(maxFiles > 0) { "maxFiles must be positive" }
        val files = if (root.isFile) listOf(root) else root.walkTopDown().filter { it.isFile }.take(maxFiles).toList()
        val findings = mutableListOf<Finding>()
        for (file in files) {
            val relative = if (root.isFile) file.name else file.relativeTo(root).path
            if (sensitiveName.containsMatchIn(file.name)) findings += Finding(relative, "filename", "sensitive-looking filename")
            if (file.length() <= 1_048_576 && isLikelyText(file)) {
                val text = runCatching { file.readText() }.getOrDefault("")
                if (sensitiveContent.containsMatchIn(text)) findings += Finding(relative, "content", "possible secret/credential indicator")
            }
        }
        return findings
    }

    private fun isLikelyText(file: File): Boolean = runCatching {
        val bytes = file.inputStream().use { it.readNBytes(1024) }
        bytes.none { it == 0.toByte() }
    }.getOrDefault(false)
}
