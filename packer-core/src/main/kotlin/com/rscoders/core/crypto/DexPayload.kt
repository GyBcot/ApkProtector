package com.rscoders.core.crypto

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.zip.Deflater
import java.util.zip.Inflater

object DexPayload {
    private val PAYLOAD_MAGIC = "CAP1".toByteArray(Charsets.US_ASCII)
    private val CONTAINER_MAGIC = "CADX".toByteArray(Charsets.US_ASCII)

    fun pack(dexBlobs: List<ByteArray>, dek: ByteArray, kek: ByteArray): ByteArray {
        val container = ByteArrayOutputStream().also { bos ->
            DataOutputStream(bos).use { d ->
                d.write(CONTAINER_MAGIC)
                d.writeInt(dexBlobs.size)
                for (dex in dexBlobs) {
                    d.writeInt(dex.size)
                    d.write(dex)
                }
            }
        }.toByteArray()

        val wrappedDek = AesGcm.encrypt(kek, dek)

        val body = AesGcm.encrypt(dek, deflate(container))

        return ByteArrayOutputStream().also { bos ->
            DataOutputStream(bos).use { d ->
                d.write(PAYLOAD_MAGIC)
                d.writeInt(wrappedDek.size); d.write(wrappedDek)
                d.writeInt(body.size); d.write(body)
            }
        }.toByteArray()
    }

    fun unpack(payload: ByteArray, kek: ByteArray): List<ByteArray> {
        DataInputStream(payload.inputStream()).use { d ->
            val magic = ByteArray(4).also(d::readFully)
            require(magic.contentEquals(PAYLOAD_MAGIC)) { "bad payload magic" }
            val wrappedDek = ByteArray(d.readInt()).also(d::readFully)
            val body = ByteArray(d.readInt()).also(d::readFully)

            val dek = AesGcm.decrypt(kek, wrappedDek)
            val container = inflate(AesGcm.decrypt(dek, body))

            DataInputStream(container.inputStream()).use { c ->
                val cmagic = ByteArray(4).also(c::readFully)
                require(cmagic.contentEquals(CONTAINER_MAGIC)) { "bad container magic" }
                val count = c.readInt()
                return (0 until count).map { ByteArray(c.readInt()).also(c::readFully) }
            }
        }
    }

    private fun deflate(data: ByteArray): ByteArray {
        val d = Deflater(Deflater.BEST_COMPRESSION)
        d.setInput(data); d.finish()
        val out = ByteArrayOutputStream(data.size / 2)
        val buf = ByteArray(64 * 1024)
        while (!d.finished()) out.write(buf, 0, d.deflate(buf))
        d.end()
        return out.toByteArray()
    }

    private fun inflate(data: ByteArray): ByteArray {
        val inf = Inflater()
        inf.setInput(data)
        val out = ByteArrayOutputStream(data.size * 2)
        val buf = ByteArray(64 * 1024)
        while (!inf.finished()) {
            val n = inf.inflate(buf)
            if (n == 0 && inf.needsInput()) break
            out.write(buf, 0, n)
        }
        inf.end()
        return out.toByteArray()
    }

    val DEFAULT_KEK: ByteArray = ByteArray(32) { (0x41 + (it % 26)).toByte() }
}
