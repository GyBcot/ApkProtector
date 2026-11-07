package com.rscoders.core

import java.io.File

data class SigningConfig(
    val keystore: File,
    val keystorePassword: String,
    val keyAlias: String,
    val keyPassword: String = keystorePassword,
    val v1Enabled: Boolean = true,
    val v2Enabled: Boolean = true,
    val v3Enabled: Boolean = true,
)

data class SslPinningConfig(
    val enabled: Boolean = false,
    val pins: List<SslPin> = emptyList(),
    val enforcePinning: Boolean = true,
    val allowUserCerts: Boolean = false,
)

data class SslPin(
    val hostname: String,
    val sha256Pins: List<String>,
    val includeSubdomains: Boolean = false,
)

data class ProtectionOptions(
    val signatureVerification: Boolean = true,
    val fileIntegrityVerification: Boolean = true,
    val debuggingDetection: Boolean = true,
    val antiReverseTools: Boolean = true,
    val screenCapturePrevention: Boolean = true,
    val antiHijacking: Boolean = true,
    val antiPtrace: Boolean = false,
    val rootDetection: Boolean = false,
    val emulatorDetection: Boolean = false,
    val doubleOpenDetection: Boolean = false,
    val accessibilityDetection: Boolean = false,
    val logSuppression: Boolean = false,
    val sslPinning: SslPinningConfig = SslPinningConfig(),
) {
    companion object {
        val DEFAULT = ProtectionOptions()
        val STRICT = ProtectionOptions(
            antiPtrace = true, rootDetection = true, emulatorDetection = true,
            doubleOpenDetection = true, accessibilityDetection = true, logSuppression = true,
        )
        val NONE = ProtectionOptions(
            signatureVerification = false, fileIntegrityVerification = false,
            debuggingDetection = false, antiPtrace = false, antiReverseTools = false,
            screenCapturePrevention = false, antiHijacking = false,
        )
    }
}

data class HardeningConfig(
    val inputApk: File,
    val outputApk: File,
    val stubDex: File? = null,
    val nativeShells: Map<String, File> = emptyMap(),
    val stubApplicationClass: String = "com.rscoders.stub.StubApp",
    val signing: SigningConfig? = null,
    val protection: ProtectionOptions = ProtectionOptions.DEFAULT,
    val protectedAssetGlobs: List<String> = emptyList(),
    val protectNativeLibs: Boolean = false,
    val workDir: File? = null,
    val keepWorkDir: Boolean = false,
)
