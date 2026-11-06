package com.rscoders.core.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object AesGcm {
    private const val IV_LEN = 12
    private const val TAG_BITS = 128
    private val rng = SecureRandom()

    fun newKey(): ByteArray = ByteArray(32).also(rng::nextBytes)

    fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
        val iv = ByteArray(IV_LEN).also(rng::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        val ct = cipher.doFinal(plaintext)
        return iv + ct
    }

    fun decrypt(key: ByteArray, ivAndCiphertext: ByteArray): ByteArray {
        val iv = ivAndCiphertext.copyOfRange(0, IV_LEN)
        val ct = ivAndCiphertext.copyOfRange(IV_LEN, ivAndCiphertext.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(ct)
    }
}
