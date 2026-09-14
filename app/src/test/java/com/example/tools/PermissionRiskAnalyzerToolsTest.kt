package com.example.tools

fun main() {
    val findings = PermissionRiskAnalyzerTools.analyze(listOf(
        "android.permission.CAMERA",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.INTERNET",
        "android.permission.CAMERA"
    ))
    check(findings.size == 3)
    check(findings.first { it.permission.endsWith("CAMERA") }.risk == PermissionRiskAnalyzerTools.Risk.HIGH)
    check(findings.first { it.permission.endsWith("POST_NOTIFICATIONS") }.risk == PermissionRiskAnalyzerTools.Risk.MEDIUM)
    check(findings.first { it.permission.endsWith("INTERNET") }.risk == PermissionRiskAnalyzerTools.Risk.LOW)
    check(PermissionRiskAnalyzerTools.analyze(listOf("", " ")).isEmpty())
    println("SMOKE_TEST_PASS")
}