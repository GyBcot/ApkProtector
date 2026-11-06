package com.rscoders.core.steps

import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class ApkRepackager {

    private val signatureFile = Regex("META-INF/.*\\.(RSA|DSA|EC|SF)", RegexOption.IGNORE_CASE)
    private val dexFile = Regex("classes\\d*\\.dex")
    private val buildMetadata = Regex(
        "META-INF/(.*\\.version|com/android/build/.*|.*\\.kotlin_module)",
        RegexOption.IGNORE_CASE,
    )

    fun repackage(
        input: File,
        output: File,
        patchedManifest: ByteArray,
        stubDex: File,
        storedEntries: Map<String, ByteArray>,
        deflatedEntries: Map<String, ByteArray>,
        skipEntries: Set<String> = emptySet(),
    ) {
        output.parentFile?.mkdirs()
        val added = HashSet<String>()

        ZipFile(input).use { zip ->
            ZipOutputStream(output.outputStream().buffered()).use { out ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    val name = e.name
                    if (name == "AndroidManifest.xml") continue
                    if (dexFile.matches(name)) continue
                    if (name == "META-INF/MANIFEST.MF") continue
                    if (signatureFile.matches(name)) continue
                    if (buildMetadata.matches(name)) continue
                    if (name in skipEntries) continue
                    if (name in storedEntries || name in deflatedEntries) continue
                    copyEntry(zip, e, out)
                    added += name
                }

                writeDeflated(out, "AndroidManifest.xml", patchedManifest)
                writeDeflated(out, "classes.dex", stubDex.readBytes())
                deflatedEntries.forEach { (n, b) -> if (added.add(n)) writeDeflated(out, n, b) }
                storedEntries.forEach { (n, b) -> if (added.add(n)) writeStored(out, n, b) }
            }
        }
    }

    private fun copyEntry(zip: ZipFile, e: ZipEntry, out: ZipOutputStream) {
        val bytes = zip.getInputStream(e).use { it.readBytes() }
        if (e.method == ZipEntry.STORED) {
            writeStored(out, e.name, bytes)
        } else {
            writeDeflated(out, e.name, bytes)
        }
    }

    private fun writeDeflated(out: ZipOutputStream, name: String, bytes: ByteArray) {
        val e = ZipEntry(name).apply { method = ZipEntry.DEFLATED }
        out.putNextEntry(e)
        out.write(bytes)
        out.closeEntry()
    }

    private fun writeStored(out: ZipOutputStream, name: String, bytes: ByteArray) {
        val crc = CRC32().apply { update(bytes) }
        val e = ZipEntry(name).apply {
            method = ZipEntry.STORED
            size = bytes.size.toLong()
            compressedSize = bytes.size.toLong()
            setCrc(crc.value)
        }
        out.putNextEntry(e)
        out.write(bytes)
        out.closeEntry()
    }
}
