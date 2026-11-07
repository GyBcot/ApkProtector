package com.rscoders.core.steps

import com.rscoders.core.SslPinningConfig
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

object NscBuilder {

    fun build(ssl: SslPinningConfig): ByteArray {
        val sb = StringBuilder()
        sb.appendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>")
        sb.appendLine("<network-security-config>")
        sb.appendLine("  <base-config cleartextTrafficPermitted=\"true\">")
        sb.appendLine("    <trust-anchors>")
        sb.appendLine("      <certificates src=\"system\" />")
        if (ssl.allowUserCerts) {
            sb.appendLine("      <certificates src=\"user\" />")
        }
        sb.appendLine("    </trust-anchors>")
        sb.appendLine("  </base-config>")

        val byHost = ssl.pins.groupBy { it.hostname }
        for ((hostname, pins) in byHost) {
            val includeSubdomains = pins.any { it.includeSubdomains }
            sb.appendLine("  <domain-config>")
            sb.appendLine("    <domain includeSubdomains=\"$includeSubdomains\">$hostname</domain>")
            if (!ssl.enforcePinning) {
                sb.appendLine("    <pin-set expiration=\"2099-01-01\">")
            } else {
                sb.appendLine("    <pin-set>")
            }
            for (pin in pins) {
                for (sha in pin.sha256Pins) {
                    sb.appendLine("      <pin digest=\"SHA-256\">$sha</pin>")
                }
            }
            sb.appendLine("    </pin-set>")
            sb.appendLine("    <trust-anchors>")
            sb.appendLine("      <certificates src=\"system\" />")
            if (ssl.allowUserCerts) {
                sb.appendLine("      <certificates src=\"user\" />")
            }
            sb.appendLine("    </trust-anchors>")
            sb.appendLine("  </domain-config>")
        }

        sb.appendLine("</network-security-config>")
        return sb.toString().toByteArray(Charsets.UTF_8)
    }
}
