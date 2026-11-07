package com.rscoders.core

import com.rscoders.core.axml.BinaryXml
import com.rscoders.core.crypto.AesGcm
import com.rscoders.core.crypto.DexPayload
import com.rscoders.core.crypto.ShellPatcher
import com.rscoders.core.sign.ApkSignerTool
import com.rscoders.core.sign.CertFingerprint
import com.rscoders.core.steps.ApkRepackager
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipFile

class HardeningPipeline(
    private val sdk: AndroidSdk = AndroidSdk.locate(),
) {
    private val repackager = ApkRepackager()
    private val signer = ApkSignerTool(sdk)

    fun harden(config: HardeningConfig): HardeningResult {
        require(config.inputApk.isFile) { "input APK not found: ${config.inputApk}" }
        val stubDex = config.stubDex
            ?: error("stubDex is required. Build it with shell-stub/build-stub.sh.")
        require(stubDex.isFile) { "stub dex not found: $stubDex" }

        val steps = mutableListOf<StepReport>()
        val work = config.workDir ?: Files.createTempDirectory("rscoders-").toFile()
        work.mkdirs()

        try {
            val (dexBlobs, manifestBytes) = readApk(config.inputApk)
            require(dexBlobs.isNotEmpty()) { "no classes*.dex in ${config.inputApk.name}" }
            steps += StepReport("read", "${dexBlobs.size} dex, ${dexBlobs.sumOf { it.size }} bytes")

            val kek = AesGcm.newKey()
            val dek = AesGcm.newKey()
            val payload = DexPayload.pack(dexBlobs, dek, kek)
            steps += StepReport("encrypt", "AES-256-GCM, per-build KEK, payload=${payload.size} bytes")

            val assetKey = deriveAssetKey(dek)
            val protectedAssets = if (config.protectedAssetGlobs.isEmpty()) emptyMap()
            else readAssets(config.inputApk, config.protectedAssetGlobs)
            val encAssets = LinkedHashMap<String, ByteArray>()
            val assetSkip = HashSet<String>()
            val protectedNames = ArrayList<String>()
            protectedAssets.forEach { (entry, bytes) ->
                val rel = entry.removePrefix("assets/")
                encAssets["assets/rscoders/enc/$rel"] = AesGcm.encrypt(assetKey, bytes)
                assetSkip += entry
                protectedNames += rel
            }
            if (protectedNames.isNotEmpty()) {
                steps += StepReport("protect-assets", "${protectedNames.size} asset(s) encrypted")
            }

            val certSha = config.signing?.let { CertFingerprint.sha256Hex(it) }
            val soKey = deriveSoKey(dek, certSha)
            val soStored = LinkedHashMap<String, ByteArray>()
            val soNames = LinkedHashSet<String>()
            if (config.protectNativeLibs) {
                readNativeLibs(config.inputApk).forEach { (entry, bytes) ->
                    soStored[entry] = AesGcm.encrypt(soKey, bytes)
                    soNames += entry.substringAfterLast('/')
                }
                if (soNames.isNotEmpty()) {
                    steps += StepReport("protect-so", "${soStored.size} lib(s), ${soNames.size} unique: ${soNames.joinToString(",")}")
                }
            }

            val patched = BinaryXml.setApplicationName(manifestBytes, config.stubApplicationClass)
            steps += StepReport(
                "patch-manifest",
                "application -> ${config.stubApplicationClass} " +
                    "(was ${patched.originalApplicationClass ?: "<default>"})",
            )

            val p = config.protection
            val ssl = p.sslPinning
            val fingerprint = UUID.randomUUID().toString()
            val payloadSha = CertFingerprint.sha256Hex(payload)
            val propsBytes = buildString {
                appendLine("rscoders.version=1")
                appendLine("rscoders.originalApplication=${patched.originalApplicationClass ?: ""}")
                appendLine("rscoders.dexCount=${dexBlobs.size}")
                appendLine("rscoders.payload=rscoders.payload")
                appendLine("rscoders.fingerprint=$fingerprint")
                appendLine("guard.payloadSha256=$payloadSha")
                certSha?.let { appendLine("guard.certSha256=$it") }
                appendLine("guard.signatureVerification=${p.signatureVerification && certSha != null}")
                appendLine("guard.fileIntegrityVerification=${p.fileIntegrityVerification}")
                appendLine("guard.debuggingDetection=${p.debuggingDetection}")
                appendLine("guard.antiPtrace=${p.antiPtrace}")
                appendLine("guard.antiReverseTools=${p.antiReverseTools}")
                appendLine("guard.screenCapturePrevention=${p.screenCapturePrevention}")
                appendLine("guard.antiHijacking=${p.antiHijacking}")
                appendLine("guard.rootDetection=${p.rootDetection}")
                appendLine("guard.emulatorDetection=${p.emulatorDetection}")
                appendLine("guard.doubleOpenDetection=${p.doubleOpenDetection}")
                appendLine("guard.accessibilityDetection=${p.accessibilityDetection}")
                appendLine("guard.logSuppression=${p.logSuppression}")
                appendLine("guard.protectedAssets=${protectedNames.joinToString(",")}")
                appendLine("guard.protectedSo=${soNames.joinToString(",")}")
                appendLine("guard.sslPinning=${ssl.enabled}")
                appendLine("guard.sslPinningEnforce=${ssl.enforcePinning}")
                appendLine("guard.sslPinningAllowUserCerts=${ssl.allowUserCerts}")
                if (ssl.enabled && ssl.pins.isNotEmpty()) {
                    val pinsJson = buildString {
                        append("[")
                        ssl.pins.forEachIndexed { idx, pin ->
                            if (idx > 0) append(",")
                            append("{")
                            append("\"host\":\"${pin.hostname}\",")
                            append("\"sub\":${pin.includeSubdomains},")
                            append("\"pins\":[${pin.sha256Pins.joinToString(",") { "\"$it\"" }}]")
                            append("}")
                        }
                        append("]")
                    }
                    appendLine("guard.sslPins=$pinsJson")
                }
            }.toByteArray()

            if (ssl.enabled && ssl.pins.isNotEmpty()) {
                steps += StepReport(
                    "ssl-pinning",
                    "${ssl.pins.size} host(s) pinned, enforce=${ssl.enforcePinning}",
                )
            }

            steps += StepReport(
                "guard",
                "fingerprint=${fingerprint.take(8)}… " +
                    "sig=${p.signatureVerification && certSha != null} integ=${p.fileIntegrityVerification} " +
                    "debug=${p.debuggingDetection} ptrace=${p.antiPtrace} frida=${p.antiReverseTools} " +
                    "root=${p.rootDetection} emu=${p.emulatorDetection} flagsecure=${p.screenCapturePrevention} " +
                    "hijack=${p.antiHijacking} dblopen=${p.doubleOpenDetection} a11y=${p.accessibilityDetection} " +
                    "logsuppress=${p.logSuppression} sslpin=${ssl.enabled}",
            )

            val propsKey = derivePropsKey(kek)
            val encryptedProps = AesGcm.encrypt(propsKey, propsBytes)
            steps += StepReport("encrypt-props", "rscoders.properties -> rscoders.bin (AES-256-GCM)")

            val deflated = buildMap {
                put("assets/rscoders.payload", payload)
                put("assets/rscoders.bin", encryptedProps)
                putAll(encAssets)
            }
            val stored = config.nativeShells.mapKeys { (abi, _) -> "lib/$abi/librscoders.so" }
                .mapValues { (_, so) -> ShellPatcher.patch(so.readBytes(), kek) } +
                soStored

            val unsigned = work.resolve("hardened-unsigned.apk")
            repackager.repackage(
                input = config.inputApk,
                output = unsigned,
                patchedManifest = patched.bytes,
                stubDex = stubDex,
                storedEntries = stored,
                deflatedEntries = deflated,
                skipEntries = assetSkip,
            )
            steps += StepReport(
                "repackage",
                "stub dex + ${config.nativeShells.size} shell(s): ${config.nativeShells.keys.joinToString(",")}",
            )

            val aligned = work.resolve("hardened-aligned.apk")
            signer.align(unsigned, aligned)
            steps += StepReport("zipalign", "4-byte aligned (-p for .so)")

            config.outputApk.parentFile?.mkdirs()
            aligned.copyTo(config.outputApk, overwrite = true)
            val signed = config.signing != null
            if (config.signing != null) {
                signer.sign(config.outputApk, config.signing)
                steps += StepReport(
                    "sign",
                    signer.verify(config.outputApk).lineSequence().firstOrNull() ?: "signed",
                )
            } else {
                steps += StepReport("sign", "SKIPPED (no signing config) — output will not install")
            }

            return HardeningResult(
                outputApk = config.outputApk,
                originalApplicationClass = patched.originalApplicationClass,
                encryptedDexCount = dexBlobs.size,
                payloadBytes = payload.size.toLong(),
                signed = signed,
                steps = steps,
            )
        } finally {
            if (!config.keepWorkDir && config.workDir == null) work.deleteRecursively()
        }
    }

    private fun readApk(apk: File): Pair<List<ByteArray>, ByteArray> {
        val dexRegex = Regex("classes\\d*\\.dex")
        val dex = sortedMapOf<String, ByteArray>()
        var manifest: ByteArray? = null
        ZipFile(apk).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                when {
                    dexRegex.matches(e.name) ->
                        dex[e.name] = zip.getInputStream(e).use { it.readBytes() }
                    e.name == "AndroidManifest.xml" ->
                        manifest = zip.getInputStream(e).use { it.readBytes() }
                }
            }
        }
        requireNotNull(manifest) { "no AndroidManifest.xml in ${apk.name}" }
        val ordered = dex.entries.sortedBy { dexIndex(it.key) }.map { it.value }
        return ordered to manifest!!
    }

    private fun dexIndex(name: String): Int =
        Regex("classes(\\d*)\\.dex").find(name)?.groupValues?.get(1)
            ?.let { if (it.isEmpty()) 1 else it.toInt() } ?: Int.MAX_VALUE

    private fun readAssets(apk: File, globs: List<String>): Map<String, ByteArray> {
        val matchers = globs.map { globToRegex(it) }
        val out = LinkedHashMap<String, ByteArray>()
        ZipFile(apk).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                if (e.isDirectory) continue
                if (e.name.startsWith("assets/") && matchers.any { it.matches(e.name) }) {
                    out[e.name] = zip.getInputStream(e).use { it.readBytes() }
                }
            }
        }
        return out
    }

    private fun globToRegex(glob: String): Regex {
        val sb = StringBuilder()
        for (c in glob) when (c) {
            '*' -> sb.append("[^/]*")
            '?' -> sb.append("[^/]")
            '.' -> sb.append("\\.")
            else -> sb.append(Regex.escape(c.toString()))
        }
        return Regex(sb.toString())
    }

    private fun deriveAssetKey(dek: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256")
            .digest(dek + "rscoders-assets".toByteArray(Charsets.US_ASCII))

    private fun deriveSoKey(dek: ByteArray, certSha: String?): ByteArray =
        MessageDigest.getInstance("SHA-256")
            .digest(dek + "rscoders-so".toByteArray(Charsets.US_ASCII) +
                (certSha ?: "").toByteArray(Charsets.US_ASCII))

    private fun derivePropsKey(kek: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256")
            .digest(kek + "rscoders-props16".toByteArray(Charsets.US_ASCII))

    private fun readNativeLibs(apk: File): Map<String, ByteArray> {
        val re = Regex("lib/[^/]+/.+\\.so")
        val out = LinkedHashMap<String, ByteArray>()
        ZipFile(apk).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                if (!e.isDirectory && re.matches(e.name) &&
                    e.name.substringAfterLast('/') != "librscoders.so"
                ) {
                    out[e.name] = zip.getInputStream(e).use { it.readBytes() }
                }
            }
        }
        return out
    }
}
