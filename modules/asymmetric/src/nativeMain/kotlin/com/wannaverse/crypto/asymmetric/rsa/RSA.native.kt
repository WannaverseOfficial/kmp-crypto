@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.wannaverse.crypto.asymmetric.rsa

import com.wannaverse.crypto.asymmetric.util.DerUtils
import com.wannaverse.crypto.asymmetric.util.SecKeyHelper
import kotlinx.cinterop.*
import platform.CoreFoundation.CFRelease
import platform.Security.*

actual object RSA {

    actual fun generateKeyPair(keySize: Int): RSAKeyPair {
        val (privRef, pubRef) = SecKeyHelper.generateKeyPair(kSecAttrKeyTypeRSA, keySize)

        // Export raw PKCS1 keys
        val pkcs1Public = SecKeyHelper.exportKey(pubRef)
        val pkcs1Private = SecKeyHelper.exportKey(privRef)

        CFRelease(privRef)
        CFRelease(pubRef)

        // Wrap in X.509 / PKCS8 for cross-platform compatibility with Android
        val x509Public = DerUtils.wrapInX509(pkcs1Public, DerUtils.RSA_ALGORITHM_IDENTIFIER)
        val pkcs8Private = DerUtils.wrapInPkcs8(pkcs1Private, DerUtils.RSA_ALGORITHM_IDENTIFIER)

        return RSAKeyPair(
            publicKey = x509Public,
            privateKey = pkcs8Private
        )
    }

    actual fun encrypt(
        publicKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding
    ): ByteArray {
        val pkcs1Key = DerUtils.stripX509Header(publicKey)
        val keyRef = SecKeyHelper.createSecKey(
            pkcs1Key, kSecAttrKeyTypeRSA, kSecAttrKeyClassPublic,
            guessRsaKeySize(pkcs1Key)
        )

        val algorithm = when (padding) {
            RSAPadding.PKCS1 -> kSecKeyAlgorithmRSAEncryptionPKCS1
            RSAPadding.OAEP_SHA1 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA1
            RSAPadding.OAEP_SHA256 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA256
        }

        val result = SecKeyHelper.sign(keyRef, algorithm, data)
        CFRelease(keyRef)
        return result
    }

    actual fun decrypt(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding
    ): ByteArray {
        val pkcs1Key = DerUtils.stripPkcs8Header(privateKey)
        val keyRef = SecKeyHelper.createSecKey(
            pkcs1Key, kSecAttrKeyTypeRSA, kSecAttrKeyClassPrivate,
            guessRsaKeySize(pkcs1Key)
        )

        val algorithm = when (padding) {
            RSAPadding.PKCS1 -> kSecKeyAlgorithmRSAEncryptionPKCS1
            RSAPadding.OAEP_SHA1 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA1
            RSAPadding.OAEP_SHA256 -> kSecKeyAlgorithmRSAEncryptionOAEPSHA256
        }

        memScoped {
            val cfData = data.usePinned { pinned ->
                platform.CoreFoundation.CFDataCreate(null, pinned.addressOf(0).reinterpret(), data.size.toLong())!!
            }
            val error = alloc<platform.CoreFoundation.CFErrorRefVar>()
            val decrypted = SecKeyCreateDecryptedData(keyRef, algorithm, cfData, error.ptr)
                ?: throw RuntimeException("Decryption failed")

            val length = platform.CoreFoundation.CFDataGetLength(decrypted).toInt()
            val result = ByteArray(length)
            val ptr = platform.CoreFoundation.CFDataGetBytePtr(decrypted)
            result.usePinned { pinned ->
                platform.posix.memcpy(pinned.addressOf(0), ptr, length.toULong())
            }

            platform.CoreFoundation.CFRelease(cfData)
            platform.CoreFoundation.CFRelease(decrypted)
            CFRelease(keyRef)
            return result
        }
    }

    actual fun verify(
        publicKey: ByteArray,
        signature: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding
    ): Boolean {
        val pkcs1Key = DerUtils.stripX509Header(publicKey)
        val keyRef = SecKeyHelper.createSecKey(
            pkcs1Key, kSecAttrKeyTypeRSA, kSecAttrKeyClassPublic,
            guessRsaKeySize(pkcs1Key)
        )

        val result = SecKeyHelper.verify(keyRef, signatureAlgorithm(padding), data, signature)
        CFRelease(keyRef)
        return result
    }

    actual fun sign(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding
    ): ByteArray {
        val pkcs1Key = DerUtils.stripPkcs8Header(privateKey)
        val keyRef = SecKeyHelper.createSecKey(
            pkcs1Key, kSecAttrKeyTypeRSA, kSecAttrKeyClassPrivate,
            guessRsaKeySize(pkcs1Key)
        )

        val result = SecKeyHelper.sign(keyRef, signatureAlgorithm(padding), data)
        CFRelease(keyRef)
        return result
    }

    private fun signatureAlgorithm(padding: RSASignaturePadding): SecKeyAlgorithm? = when (padding) {
        RSASignaturePadding.PKCS1_SHA256 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
        RSASignaturePadding.PKCS1_SHA384 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384
        RSASignaturePadding.PKCS1_SHA512 -> kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
        RSASignaturePadding.PSS_SHA256 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA256
        RSASignaturePadding.PSS_SHA384 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA384
        RSASignaturePadding.PSS_SHA512 -> kSecKeyAlgorithmRSASignatureMessagePSSSHA512
    }

    /**
     * Estimates the RSA key size from PKCS1 encoded key data.
     * The modulus is the first INTEGER in the SEQUENCE, and its bit length is the key size.
     */
    private fun guessRsaKeySize(pkcs1Key: ByteArray): Int {
        // PKCS1: SEQUENCE { INTEGER(modulus), ... }
        // Read past the SEQUENCE tag+length to the first INTEGER
        var offset = 0
        if ((pkcs1Key[offset].toInt() and 0xFF) == 0x30) {
            offset++
            val (_, lenSize) = DerUtils.readDerLength(pkcs1Key, offset)
            offset += lenSize
        }
        // First element: INTEGER (modulus for public, version for private)
        if ((pkcs1Key[offset].toInt() and 0xFF) == 0x02) {
            offset++
            val (intLen, lenSize) = DerUtils.readDerLength(pkcs1Key, offset)
            offset += lenSize
            // Skip leading zero byte if present
            val leadingZero = if (pkcs1Key[offset] == 0.toByte()) 1 else 0
            val modulusBits = (intLen - leadingZero) * 8
            // For private keys, first INTEGER is version 0, second is modulus
            if (modulusBits <= 8) {
                // This was version, skip to next INTEGER (modulus)
                offset += intLen
                if ((pkcs1Key[offset].toInt() and 0xFF) == 0x02) {
                    offset++
                    val (modLen, modLenSize) = DerUtils.readDerLength(pkcs1Key, offset)
                    offset += modLenSize
                    val modLeadingZero = if (pkcs1Key[offset] == 0.toByte()) 1 else 0
                    return (modLen - modLeadingZero) * 8
                }
            }
            return modulusBits
        }
        return 2048 // fallback
    }
}
