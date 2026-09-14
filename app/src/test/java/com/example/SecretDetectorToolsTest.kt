import com.example.tools.SecretDetectorTools

fun main() {
    val text = "api_key=sk_test_EXAMPLE12345 and AKIA1234567890ABCDEF\n-----BEGIN RSA PRIVATE KEY-----"
    val findings = SecretDetectorTools.scan(text)
    check(findings.any { it.type == "Generic assignment secret" })
    check(findings.any { it.type == "AWS access key" })
    check(findings.any { it.type == "Private key" })
    check(findings.all { !it.redacted.contains("EXAMPLE12345") && !it.redacted.contains("1234567890ABCDEF") })
    check(SecretDetectorTools.scan("nothing sensitive here").isEmpty())
    println("SMOKE_TEST_PASS")
}
