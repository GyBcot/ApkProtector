package com.rscoders.core.axml

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

object BinaryXml {

    private const val TYPE_XML = 0x0003
    private const val TYPE_STRING_POOL = 0x0001
    private const val TYPE_RESOURCE_MAP = 0x0180
    private const val TYPE_START_ELEMENT = 0x0102
    private const val UTF8_FLAG = 0x0100
    private const val ATTR_TYPE_STRING = 0x03
    private const val ATTR_TYPE_REFERENCE = 0x01
    private const val ANDROID_URI = "http://schemas.android.com/apk/res/android"
    private const val ANDROID_RES_ID_NAME = 0x0101021B
    private const val ANDROID_RES_ID_NSC = 0x010104EC

    data class Result(val bytes: ByteArray, val originalApplicationClass: String?)

    fun setApplicationName(manifest: ByteArray, stubClass: String, nscResId: Int? = null): Result {
        val buf = ByteBuffer.wrap(manifest).order(ByteOrder.LITTLE_ENDIAN)

        require(buf.getShort(0).toInt() and 0xFFFF == TYPE_XML) { "not a binary XML file" }
        val poolOff = 8
        require(buf.getShort(poolOff).toInt() and 0xFFFF == TYPE_STRING_POOL) { "expected string pool" }
        val poolSize = buf.getInt(poolOff + 4)
        val stringCount = buf.getInt(poolOff + 8)
        val styleCount = buf.getInt(poolOff + 12)
        val flags = buf.getInt(poolOff + 16)
        val stringsStart = buf.getInt(poolOff + 20)
        require(styleCount == 0) { "styled string pools are not supported" }
        val utf8 = flags and UTF8_FLAG != 0

        val strings = readStrings(buf, poolOff, stringCount, stringsStart, utf8)
        val nameIdx = strings.indexOf("name")
        require(nameIdx >= 0) { "no \"name\" string in pool; unusual manifest" }
        val androidUriIdx = strings.indexOf(ANDROID_URI)
        val nscAttrName = "networkSecurityConfig"

        var newPool: ByteArray
        var stubIdx = stringCount
        var nscAttrIdx = -1
        var nscStrIdx = -1

        if (nscResId != null) {
            val nscResPath = "@xml/rscoders_nsc"
            newPool = appendString(buf, poolOff, poolSize, stringCount, stringsStart, utf8, stubClass)
            val poolAfterStub = newPool
            val countAfterStub = stringCount + 1
            nscAttrIdx = countAfterStub
            newPool = appendStringToPool(poolAfterStub, utf8, nscAttrName)
            nscStrIdx = countAfterStub + 1
            newPool = appendStringToPool(newPool, utf8, nscResPath)
        } else {
            newPool = appendString(buf, poolOff, poolSize, stringCount, stringsStart, utf8, stubClass)
        }

        val tailStart = poolOff + poolSize
        val tail = manifest.copyOfRange(tailStart, manifest.size)
        val edit = editApplication(tail, strings, nameIdx, androidUriIdx, stubIdx, nscResId, nscAttrIdx, nscStrIdx)
        val total = 8 + newPool.size + edit.tail.size
        val out = ByteArrayOutputStream(total)
        val header = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        header.putShort(TYPE_XML.toShort()); header.putShort(8); header.putInt(total)
        out.write(header.array())
        out.write(newPool)
        out.write(edit.tail)
        return Result(out.toByteArray(), edit.originalClass)
    }

    private data class TailEdit(val tail: ByteArray, val originalClass: String?)

    private fun editApplication(
        tail: ByteArray,
        strings: List<String>,
        nameIdx: Int,
        androidUriIdx: Int,
        stubIdx: Int,
        nscResId: Int?,
        nscAttrIdx: Int,
        nscStrIdx: Int,
    ): TailEdit {
        val buf = ByteBuffer.wrap(tail).order(ByteOrder.LITTLE_ENDIAN)
        val resMap = readResourceMap(buf, tail.size)
        var pos = 0
        while (pos + 8 <= tail.size) {
            val type = buf.getShort(pos).toInt() and 0xFFFF
            val size = buf.getInt(pos + 4)
            require(size > 0) { "zero-size chunk at $pos" }
            if (type == TYPE_START_ELEMENT) {
                val name = buf.getInt(pos + 20)
                if (strings.getOrNull(name) == "application") {
                    return patchElement(tail, pos, strings, nameIdx, androidUriIdx, stubIdx, resMap, nscResId, nscAttrIdx, nscStrIdx)
                }
            }
            pos += size
        }
        error("no <application> element found in manifest")
    }

    private fun readResourceMap(buf: ByteBuffer, tailSize: Int): IntArray {
        var pos = 0
        while (pos + 8 <= tailSize) {
            val type = buf.getShort(pos).toInt() and 0xFFFF
            val size = buf.getInt(pos + 4)
            if (size <= 0) break
            if (type == TYPE_RESOURCE_MAP) {
                val count = (size - 8) / 4
                return IntArray(count) { buf.getInt(pos + 8 + it * 4) }
            }
            if (type == TYPE_START_ELEMENT) break
            pos += size
        }
        return IntArray(0)
    }

    private fun patchElement(
        tail: ByteArray,
        elem: Int,
        strings: List<String>,
        nameIdx: Int,
        androidUriIdx: Int,
        stubIdx: Int,
        resMap: IntArray,
        nscResId: Int?,
        nscAttrIdx: Int,
        nscStrIdx: Int,
    ): TailEdit {
        val buf = ByteBuffer.wrap(tail).order(ByteOrder.LITTLE_ENDIAN)
        val attrCount = buf.getShort(elem + 28).toInt() and 0xFFFF
        val attrsStart = elem + 36

        var originalClass: String? = null
        var namePatched = false

        for (i in 0 until attrCount) {
            val a = attrsStart + i * 20
            val ns = buf.getInt(a)
            val nm = buf.getInt(a + 4)
            if (nm == nameIdx && ns == androidUriIdx) {
                originalClass = strings.getOrNull(buf.getInt(a + 16))
                buf.putInt(a + 8, stubIdx)
                buf.putInt(a + 16, stubIdx)
                namePatched = true
                break
            }
        }

        var workingTail = tail
        var workingBuf = ByteBuffer.wrap(workingTail).order(ByteOrder.LITTLE_ENDIAN)
        var currentAttrCount = attrCount

        if (!namePatched) {
            require(androidUriIdx >= 0) { "android namespace URI missing; cannot insert android:name" }
            val newResId = resMap.getOrElse(nameIdx) { 0 }
            var insIdx = currentAttrCount
            for (i in 0 until currentAttrCount) {
                val attrNameIdx = workingBuf.getInt(attrsStart + i * 20 + 4)
                val resId = resMap.getOrElse(attrNameIdx) { 0 }
                if ((resId == 0) || (java.lang.Integer.compareUnsigned(resId, newResId) > 0)) {
                    insIdx = i; break
                }
            }
            val insertAt = attrsStart + insIdx * 20
            val attr = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
            attr.putInt(androidUriIdx)
            attr.putInt(nameIdx)
            attr.putInt(stubIdx)
            attr.putShort(8)
            attr.put(0)
            attr.put(ATTR_TYPE_STRING.toByte())
            attr.putInt(stubIdx)
            val out = ByteArray(workingTail.size + 20)
            System.arraycopy(workingTail, 0, out, 0, insertAt)
            System.arraycopy(attr.array(), 0, out, insertAt, 20)
            System.arraycopy(workingTail, insertAt, out, insertAt + 20, workingTail.size - insertAt)
            workingTail = out
            workingBuf = ByteBuffer.wrap(workingTail).order(ByteOrder.LITTLE_ENDIAN)
            workingBuf.putInt(elem + 4, workingBuf.getInt(elem + 4) + 20)
            currentAttrCount++
            workingBuf.putShort(elem + 28, currentAttrCount.toShort())
            for (off in intArrayOf(30, 32, 34)) {
                val si = workingBuf.getShort(elem + off).toInt() and 0xFFFF
                if (si != 0 && si > insIdx) workingBuf.putShort(elem + off, (si + 1).toShort())
            }
        }

        if (nscResId != null) {
            val nscResIdInt = nscResId
            val existingNscAttr = (0 until currentAttrCount).any { i ->
                val a = attrsStart + i * 20
                workingBuf.getInt(a + 4) == nscAttrIdx
            }
            if (!existingNscAttr) {
                val insertAt = attrsStart + currentAttrCount * 20
                val attr = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
                attr.putInt(androidUriIdx)
                attr.putInt(nscAttrIdx)
                attr.putInt(nscStrIdx)
                attr.putShort(8)
                attr.put(0)
                attr.put(ATTR_TYPE_REFERENCE.toByte())
                attr.putInt(nscResIdInt)
                val out = ByteArray(workingTail.size + 20)
                System.arraycopy(workingTail, 0, out, 0, insertAt)
                System.arraycopy(attr.array(), 0, out, insertAt, 20)
                System.arraycopy(workingTail, insertAt, out, insertAt + 20, workingTail.size - insertAt)
                workingTail = out
                workingBuf = ByteBuffer.wrap(workingTail).order(ByteOrder.LITTLE_ENDIAN)
                workingBuf.putInt(elem + 4, workingBuf.getInt(elem + 4) + 20)
                currentAttrCount++
                workingBuf.putShort(elem + 28, currentAttrCount.toShort())
            }
        }

        return TailEdit(workingTail, originalClass)
    }

    private fun readStrings(
        buf: ByteBuffer,
        poolOff: Int,
        count: Int,
        stringsStart: Int,
        utf8: Boolean,
    ): List<String> {
        val offsetsBase = poolOff + 28
        val dataBase = poolOff + stringsStart
        return (0 until count).map { i ->
            val off = buf.getInt(offsetsBase + i * 4)
            decodeString(buf, dataBase + off, utf8)
        }
    }

    private fun decodeString(buf: ByteBuffer, at: Int, utf8: Boolean): String {
        return if (utf8) {
            var p = at
            p = skipLen8(buf, p)
            val (byteLen, p2) = readLen8(buf, p)
            val bytes = ByteArray(byteLen)
            for (j in 0 until byteLen) bytes[j] = buf.get(p2 + j)
            String(bytes, Charsets.UTF_8)
        } else {
            var len = buf.getShort(at).toInt() and 0xFFFF
            var p = at + 2
            if (len and 0x8000 != 0) {
                len = ((len and 0x7FFF) shl 16) or (buf.getShort(p).toInt() and 0xFFFF)
                p += 2
            }
            val chars = CharArray(len)
            for (j in 0 until len) chars[j] = buf.getShort(p + j * 2).toInt().toChar()
            String(chars)
        }
    }

    private fun skipLen8(buf: ByteBuffer, p: Int): Int {
        val v = buf.get(p).toInt() and 0xFF
        return if (v and 0x80 != 0) p + 2 else p + 1
    }

    private fun readLen8(buf: ByteBuffer, p: Int): Pair<Int, Int> {
        val v = buf.get(p).toInt() and 0xFF
        return if (v and 0x80 != 0) {
            val v2 = buf.get(p + 1).toInt() and 0xFF
            Pair(((v and 0x7F) shl 8) or v2, p + 2)
        } else {
            Pair(v, p + 1)
        }
    }

    private fun appendString(
        buf: ByteBuffer,
        poolOff: Int,
        poolSize: Int,
        count: Int,
        stringsStart: Int,
        utf8: Boolean,
        newString: String,
    ): ByteArray {
        val oldOffsetsBase = poolOff + 28
        val oldDataBase = poolOff + stringsStart
        val oldDataLen = poolSize - stringsStart
        val encoded = if (utf8) encodeUtf8(newString) else encodeUtf16(newString)
        val newCount = count + 1
        val newStringsStart = 28 + newCount * 4
        var dataLen = oldDataLen + encoded.size
        val pad = (4 - (newStringsStart + dataLen) % 4) % 4
        dataLen += pad
        val newPoolSize = newStringsStart + dataLen
        val out = ByteBuffer.allocate(newPoolSize).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(TYPE_STRING_POOL.toShort())
        out.putShort(28)
        out.putInt(newPoolSize)
        out.putInt(newCount)
        out.putInt(0)
        out.putInt(buf.getInt(poolOff + 16))
        out.putInt(newStringsStart)
        out.putInt(0)
        for (i in 0 until count) out.putInt(buf.getInt(oldOffsetsBase + i * 4))
        out.putInt(oldDataLen)
        for (i in 0 until oldDataLen) out.put(buf.get(oldDataBase + i))
        out.put(encoded)
        repeat(pad) { out.put(0) }
        return out.array()
    }

    private fun appendStringToPool(pool: ByteArray, utf8: Boolean, newString: String): ByteArray {
        val poolBuf = ByteBuffer.wrap(pool).order(ByteOrder.LITTLE_ENDIAN)
        val poolSize = poolBuf.getInt(4)
        val count = poolBuf.getInt(8)
        val stringsStart = poolBuf.getInt(20)
        val flags = poolBuf.getInt(16)
        val oldDataBase = stringsStart
        val oldDataLen = poolSize - stringsStart
        val encoded = if (utf8) encodeUtf8(newString) else encodeUtf16(newString)
        val newCount = count + 1
        val newStringsStart = 28 + newCount * 4
        var dataLen = oldDataLen + encoded.size
        val pad = (4 - (newStringsStart + dataLen) % 4) % 4
        dataLen += pad
        val newPoolSize = newStringsStart + dataLen
        val out = ByteBuffer.allocate(newPoolSize).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(TYPE_STRING_POOL.toShort())
        out.putShort(28)
        out.putInt(newPoolSize)
        out.putInt(newCount)
        out.putInt(0)
        out.putInt(flags)
        out.putInt(newStringsStart)
        out.putInt(0)
        for (i in 0 until count) out.putInt(poolBuf.getInt(28 + i * 4))
        out.putInt(oldDataLen)
        for (i in 0 until oldDataLen) out.put(pool[oldDataBase + i])
        out.put(encoded)
        repeat(pad) { out.put(0) }
        return out.array()
    }

    private fun encodeUtf16(s: String): ByteArray {
        val out = ByteBuffer.allocate(2 + s.length * 2 + 2).order(ByteOrder.LITTLE_ENDIAN)
        out.putShort(s.length.toShort())
        for (c in s) out.putShort(c.code.toShort())
        out.putShort(0)
        return out.array()
    }

    private fun encodeUtf8(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream()
        out.write(s.length and 0xFF)
        out.write(bytes.size and 0xFF)
        out.write(bytes)
        out.write(0)
        return out.toByteArray()
    }
}
