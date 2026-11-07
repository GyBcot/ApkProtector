package com.rscoders.core.crypto

object ShellPatcher {
    private val MAGIC = byteArrayOf(
        0xCA.toByte(), 0x1B, 0x0B, 0x1E, 0x5E, 0xC0.toByte(), 0xDE.toByte(), 0x4B,
        0x45, 0x4B, 0x21, 0x76, 0x31, 0x00, 0xA5.toByte(), 0x5A,
    )
    const val KEK_LEN = 32

    fun patch(soBytes: ByteArray, kek: ByteArray): ByteArray {
        require(kek.size == KEK_LEN) { "KEK must be $KEK_LEN bytes" }
        val at = indexOf(soBytes, MAGIC)
        require(at >= 0) {
            "KEK marker not found in librscoders.so — rebuild the shell (shell-native/build-native.sh)"
        }
        val out = soBytes.copyOf()
        System.arraycopy(kek, 0, out, at + MAGIC.size, KEK_LEN)
        return out
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }
}
