package com.rscoders.core.crypto

object AesGcm {
    fun newKey(): ByteArray = RsCodersKdf.newKey()
    fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray = RsCodersKdf.encrypt(key, plaintext)
    fun decrypt(key: ByteArray, ivAndCiphertext: ByteArray): ByteArray = RsCodersKdf.decrypt(key, ivAndCiphertext)
}
