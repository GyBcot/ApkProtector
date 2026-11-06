package com.rscoders.core.sign

import com.rscoders.core.AndroidSdk
import com.rscoders.core.SigningConfig
import com.rscoders.core.util.ProcessRunner
import java.io.File

class ApkSignerTool(private val sdk: AndroidSdk) {

    fun align(input: File, output: File): File {
        output.parentFile?.mkdirs()
        ProcessRunner.run(
            listOf(
                sdk.zipalign.absolutePath,
                "-p", "-f", "4",
                input.absolutePath,
                output.absolutePath,
            ),
        ).orThrow()
        return output
    }

    fun sign(apk: File, cfg: SigningConfig): File {
        val cmd = mutableListOf(
            sdk.apksigner.absolutePath, "sign",
            "--ks", cfg.keystore.absolutePath,
            "--ks-pass", "pass:${cfg.keystorePassword}",
            "--ks-key-alias", cfg.keyAlias,
            "--key-pass", "pass:${cfg.keyPassword}",
            "--v1-signing-enabled", cfg.v1Enabled.toString(),
            "--v2-signing-enabled", cfg.v2Enabled.toString(),
            "--v3-signing-enabled", cfg.v3Enabled.toString(),
            apk.absolutePath,
        )
        ProcessRunner.run(cmd).orThrow()
        return apk
    }

    fun verify(apk: File): String =
        ProcessRunner.run(
            listOf(sdk.apksigner.absolutePath, "verify", "--verbose", apk.absolutePath),
        ).orThrow().stdout
}
