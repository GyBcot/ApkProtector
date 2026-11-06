package com.rscoders.core

import java.io.File
import java.util.Properties

class AndroidSdk private constructor(
    val sdkDir: File,
    val buildToolsVersion: String,
    val ndkVersion: String?,
    val apktool: String,
) {
    private val buildTools: File = sdkDir.resolve("build-tools/$buildToolsVersion").also {
        require(it.isDirectory) { "build-tools $buildToolsVersion not found at $it" }
    }

    val zipalign: File get() = tool("zipalign")
    val apksigner: File get() = tool("apksigner")
    val d8: File get() = tool("d8")
    val aapt2: File get() = tool("aapt2")

    val ndkDir: File?
        get() = ndkVersion?.let { sdkDir.resolve("ndk/$it").takeIf(File::isDirectory) }

    private fun tool(name: String): File {
        val f = buildTools.resolve(name)
        require(f.exists()) { "$name not found in $buildTools" }
        return f
    }

    companion object {
        fun locate(
            startDir: File = File("."),
            sdkDir: File? = null,
            buildToolsVersion: String? = null,
            ndkVersion: String? = null,
        ): AndroidSdk {
            val props = readLocalProperties(startDir)
            val resolvedSdk = sdkDir
                ?: System.getenv("ANDROID_HOME")?.let(::File)
                ?: System.getenv("ANDROID_SDK_ROOT")?.let(::File)
                ?: props.getProperty("sdk.dir")?.let(::File)
                ?: error(
                    "Android SDK not found. Set ANDROID_HOME, pass sdkDir, or add " +
                        "sdk.dir=... to local.properties.",
                )
            require(resolvedSdk.isDirectory) { "sdk.dir does not exist: $resolvedSdk" }

            val btv = buildToolsVersion
                ?: props.getProperty("rscoders.buildToolsVersion")
                ?: latestBuildTools(resolvedSdk)
                ?: error("No build-tools found under $resolvedSdk/build-tools")

            val ndkv = ndkVersion
                ?: props.getProperty("rscoders.ndkVersion")
                ?: latestNdk(resolvedSdk)

            val apktool = props.getProperty("rscoders.apktool") ?: "apktool"

            return AndroidSdk(resolvedSdk, btv, ndkv, apktool)
        }

        private fun readLocalProperties(startDir: File): Properties {
            val props = Properties()
            var dir: File? = startDir.absoluteFile
            while (dir != null) {
                val f = dir.resolve("local.properties")
                if (f.isFile) {
                    f.inputStream().use(props::load)
                    break
                }
                dir = dir.parentFile
            }
            return props
        }

        private fun latestBuildTools(sdk: File): String? =
            sdk.resolve("build-tools").listFiles()?.filter(File::isDirectory)
                ?.map(File::getName)?.maxWithOrNull(::compareVersions)

        private fun latestNdk(sdk: File): String? =
            sdk.resolve("ndk").listFiles()?.filter(File::isDirectory)
                ?.map(File::getName)?.maxWithOrNull(::compareVersions)

        private fun compareVersions(a: String, b: String): Int {
            val pa = a.split(".").map { it.toIntOrNull() ?: 0 }
            val pb = b.split(".").map { it.toIntOrNull() ?: 0 }
            for (i in 0 until maxOf(pa.size, pb.size)) {
                val c = (pa.getOrElse(i) { 0 }).compareTo(pb.getOrElse(i) { 0 })
                if (c != 0) return c
            }
            return 0
        }
    }
}
