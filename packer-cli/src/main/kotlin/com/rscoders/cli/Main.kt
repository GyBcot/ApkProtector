package com.rscoders.cli

import com.rscoders.core.AndroidSdk
import com.rscoders.core.HardeningConfig
import com.rscoders.core.HardeningPipeline
import com.rscoders.core.ProtectionOptions
import com.rscoders.core.SigningConfig
import com.rscoders.core.SslPin
import com.rscoders.core.SslPinningConfig
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.file
import java.io.File

class Harden : CliktCommand(name = "harden") {
    override fun help(context: com.github.ajalt.clikt.core.Context) =
        "Harden an APK: encrypt its DEX behind the RSCoders stub loader, then re-sign."

    private val input by option("-i", "--input").file(mustExist = true, canBeDir = false).required()
    private val output by option("-o", "--output").file().required()
    private val stubDex by option("--stub-dex").file(mustExist = true).required()
    private val arm64 by option("--shell-arm64").file(mustExist = true)
    private val arm32 by option("--shell-arm32").file(mustExist = true)
    private val keepWork by option("--keep-work").flag(default = false)

    private val keystore by option("--ks").file(mustExist = true)
    private val ksPass by option("--ks-pass")
    private val keyAlias by option("--ks-alias")

    private val protectionPreset by option(
        "--protection",
        help = "runtime guard preset: default | strict | none",
    ).default("default")
    private val antiPtrace by option("--anti-ptrace").flag(default = false)
    private val rootDetection by option("--root-detection").flag(default = false)
    private val emulatorDetection by option("--emulator-detection").flag(default = false)
    private val doubleOpen by option("--double-open").flag(default = false)
    private val accessibility by option("--accessibility").flag(default = false)
    private val logSuppress by option("--log-suppress").flag(default = false)
    private val noSecureScreen by option(
        "--no-secure-screen",
        help = "disable FLAG_SECURE (allow screenshots and screen recording)",
    ).flag(default = false)
    private val protectAsset by option(
        "--protect-asset",
        help = "glob of assets to encrypt, e.g. assets/config/*.json (repeatable)",
    ).multiple()
    private val protectSo by option(
        "--protect-so",
        help = "encrypt the app's own native libraries (transparent in-memory load)",
    ).flag(default = false)

    private val sslPin by option(
        "--ssl-pin",
        help = "SSL pin: format hostname:sha256base64 (repeatable, use * prefix for subdomains)",
    ).multiple()
    private val noSslPinEnforce by option(
        "--no-ssl-pin-enforce",
        help = "report SSL pinning failures via log instead of killing the process",
    ).flag(default = false)
    private val sslPinAllowUserCerts by option(
        "--ssl-pin-allow-user-certs",
        help = "allow user-installed CA certificates alongside pins",
    ).flag(default = false)

    override fun run() {
        val shells = buildMap {
            arm64?.let { put("arm64-v8a", it) }
            arm32?.let { put("armeabi-v7a", it) }
        }
        val signing = keystore?.let {
            SigningConfig(
                keystore = it,
                keystorePassword = requireNotNull(ksPass) { "--ks-pass required with --ks" },
                keyAlias = requireNotNull(keyAlias) { "--ks-alias required with --ks" },
            )
        }

        val base = when (protectionPreset.lowercase()) {
            "strict" -> ProtectionOptions.STRICT
            "none" -> ProtectionOptions.NONE
            else -> ProtectionOptions.DEFAULT
        }

        val parsedPins = parseSslPins(sslPin)
        val sslPinningConfig = SslPinningConfig(
            enabled = parsedPins.isNotEmpty(),
            pins = parsedPins,
            enforcePinning = !noSslPinEnforce,
            allowUserCerts = sslPinAllowUserCerts,
        )

        val protection = base.copy(
            antiPtrace = base.antiPtrace || antiPtrace,
            rootDetection = base.rootDetection || rootDetection,
            emulatorDetection = base.emulatorDetection || emulatorDetection,
            doubleOpenDetection = base.doubleOpenDetection || doubleOpen,
            accessibilityDetection = base.accessibilityDetection || accessibility,
            logSuppression = base.logSuppression || logSuppress,
            screenCapturePrevention = if (noSecureScreen) false else base.screenCapturePrevention,
            sslPinning = sslPinningConfig,
        )

        val pipeline = HardeningPipeline(AndroidSdk.locate())
        val result = pipeline.harden(
            HardeningConfig(
                inputApk = input,
                outputApk = output,
                stubDex = stubDex,
                nativeShells = shells,
                signing = signing,
                protection = protection,
                protectedAssetGlobs = protectAsset,
                protectNativeLibs = protectSo,
                keepWorkDir = keepWork,
                workDir = if (keepWork) File("work/cli") else null,
            ),
        )

        echo("✔ hardened: ${result.outputApk}")
        echo("  original Application : ${result.originalApplicationClass ?: "<default>"}")
        echo("  encrypted DEX        : ${result.encryptedDexCount}")
        echo("  payload              : ${result.payloadBytes} bytes")
        echo("  signed               : ${result.signed}")
        echo("  screen capture       : ${if (protection.screenCapturePrevention) "disabled" else "allowed"}")
        echo("  ssl pinning          : ${if (sslPinningConfig.enabled) "${sslPinningConfig.pins.size} host(s)" else "disabled"}")
        result.steps.forEach { echo("  • ${it.name}: ${it.detail}") }
    }

    private fun parseSslPins(raw: List<String>): List<SslPin> {
        val map = LinkedHashMap<String, Pair<Boolean, MutableList<String>>>()
        for (entry in raw) {
            val colon = entry.lastIndexOf(':')
            require(colon > 0) { "Invalid --ssl-pin format '$entry', expected hostname:sha256base64" }
            val hostRaw = entry.substring(0, colon)
            val pin = entry.substring(colon + 1)
            val includeSub = hostRaw.startsWith("*.")
            val host = if (includeSub) hostRaw.removePrefix("*.") else hostRaw
            val (_, pins) = map.getOrPut(host) { Pair(includeSub, mutableListOf()) }
            pins += pin
        }
        return map.map { (host, pair) ->
            SslPin(hostname = host, sha256Pins = pair.second, includeSubdomains = pair.first)
        }
    }
}

fun main(args: Array<String>) = Harden().main(args)
