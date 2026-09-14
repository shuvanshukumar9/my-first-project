package com.example.tools

import java.util.Base64

/** Offline JWT inspector. Decodes structure only; never verifies, cracks, or sends tokens. */
object JwtInspectorTools {
    data class Inspection(val headerJson: String, val payloadJson: String, val signaturePresent: Boolean, val warnings: List<String>)

    fun inspect(token: String): Inspection {
        val parts = token.trim().split('.')
        require(parts.size == 3) { "JWT must contain exactly three dot-separated parts" }
        val header = decode(parts[0])
        val payload = decode(parts[1])
        val warnings = mutableListOf<String>()
        if (header.contains("\"alg\"", ignoreCase = true) && header.contains("\"alg\"\\s*:\\s*\"none\"".toRegex()))
            warnings += "algorithm is none"
        if (payload.contains("\"exp\"")) warnings += "expiration claim present; validate it in the consuming application"
        if (payload.contains("\"iss\"")) warnings += "issuer claim present"
        if (payload.contains("\"aud\"")) warnings += "audience claim present"
        return Inspection(header, payload, parts[2].isNotEmpty(), warnings)
    }

    private fun decode(part: String): String = try {
        Base64.getUrlDecoder().decode(part).toString(Charsets.UTF_8)
    } catch (_: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid base64url JWT segment")
    }
}
