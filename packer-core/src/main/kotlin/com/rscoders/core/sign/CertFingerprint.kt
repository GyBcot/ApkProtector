package com.rscoders.core.sign

import com.rscoders.core.SigningConfig
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate

object CertFingerprint {

    fun sha256Hex(cfg: SigningConfig): String {
        val ksType = if (cfg.keystore.name.endsWith(".p12", true) ||
            cfg.keystore.name.endsWith(".pfx", true)
        ) "PKCS12" else "JKS"
        val ks = KeyStore.getInstance(ksType)
        cfg.keystore.inputStream().use { ks.load(it, cfg.keystorePassword.toCharArray()) }
        val cert = ks.getCertificate(cfg.keyAlias) as? X509Certificate
            ?: error("no certificate for alias '${cfg.keyAlias}' in ${cfg.keystore}")
        return sha256Hex(cert.encoded)
    }

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
