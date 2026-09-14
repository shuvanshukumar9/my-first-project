package com.example.tools

/** Offline Android permission risk classifier. It never requests or exploits permissions. */
object PermissionRiskAnalyzerTools {
    enum class Risk { LOW, MEDIUM, HIGH }

    data class Finding(val permission: String, val risk: Risk, val guidance: String)

    private val high = setOf(
        "android.permission.READ_SMS", "android.permission.SEND_SMS",
        "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CONTACTS"
    )
    private val medium = setOf(
        "android.permission.ACCESS_COARSE_LOCATION", "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO", "android.permission.POST_NOTIFICATIONS",
        "android.permission.BLUETOOTH_CONNECT"
    )

    fun analyze(permissions: List<String>): List<Finding> = permissions
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .distinct()
        .map { permission ->
            val risk = when {
                permission in high -> Risk.HIGH
                permission in medium -> Risk.MEDIUM
                else -> Risk.LOW
            }
            val guidance = when (risk) {
                Risk.HIGH -> "Review necessity and user disclosure before requesting this permission"
                Risk.MEDIUM -> "Request only when the related feature is needed"
                Risk.LOW -> "Still review whether the permission is necessary"
            }
            Finding(permission, risk, guidance)
        }
}