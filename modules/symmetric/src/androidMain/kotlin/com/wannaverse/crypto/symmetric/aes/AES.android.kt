package com.wannaverse.crypto.symmetric.aes

import com.wannaverse.crypto.symmetric.exceptions.SymmetricCryptoException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import javax.crypto.KeyGenerator

actual class AES {
    private val secureRandom = SecureRandom()

    @Synchronized
    actual fun encrypt(plaintext: ByteArray, key: ByteArray, config: AESConfig): ByteArray {
        validateKeySize(key, config.keySize)
        val cipher = Cipher.getInstance(config.mode.cipherMode)
        val secretKey = SecretKeySpec(key, "AES")
        val ivSize = if (config.mode == AESMode.GCM) 12 else 16
        val iv = config.iv ?: ByteArray(ivSize).also { secureRandom.nextBytes(it) }

        try {
            when (config.mode) {
                AESMode.GCM -> {
                    val gcmParameterSpec = GCMParameterSpec(config.tagLength, iv)
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec)
                    config.aad?.let { cipher.updateAAD(it) }
                }
                AESMode.CBC,
                AESMode.CFB,
                AESMode.OFB,
                AESMode.CTR -> {
                    val ivSpec = IvParameterSpec(iv)
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
                }
                AESMode.ECB -> {
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
                }
            }
            return iv + cipher.doFinal(plaintext)
        } catch (e: Exception) {
            throw SymmetricCryptoException("Encryption failed", e)
        }
    }

    @Synchronized
    actual fun decrypt(ciphertext: ByteArray, key: ByteArray, config: AESConfig): ByteArray {
        validateKeySize(key, config.keySize)
        val cipher = Cipher.getInstance(config.mode.cipherMode)
        val secretKey = SecretKeySpec(key, "AES")
        val ivSize = if (config.mode == AESMode.GCM) 12 else 16
        val iv = config.iv ?: ciphertext.copyOfRange(0, ivSize)
        val encryptedData = if (config.iv == null) ciphertext.copyOfRange(ivSize, ciphertext.size) else ciphertext

        try {
            when (config.mode) {
                AESMode.GCM -> {
                    val gcmParameterSpec = GCMParameterSpec(config.tagLength, iv)
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec)
                    config.aad?.let { cipher.updateAAD(it) }
                }
                AESMode.CBC,
                AESMode.CFB,
                AESMode.OFB,
                AESMode.CTR -> {
                    val ivSpec = IvParameterSpec(iv)
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
                }
                AESMode.ECB -> {
                    cipher.init(Cipher.DECRYPT_MODE, secretKey)
                }
            }
            return cipher.doFinal(encryptedData)
        } catch (e: Exception) {
            throw SymmetricCryptoException("Decryption failed", e)
        }
    }

    actual fun createKey(keySize: KeySize): ByteArray {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(keySize.bits)
        return keyGen.generateKey().encoded
    }

    private fun validateKeySize(key: ByteArray, keySize: KeySize) {
        val expectedBytes = keySize.bits / 8
        require(key.size == expectedBytes) { "Key size must be ${keySize.bits} bits" }
    }
}