@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.wannaverse.crypto.asymmetric.util

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Security.*

/**
 * Helper for iOS Security framework SecKey operations.
 */
internal object SecKeyHelper {

    /**
     * Creates a SecKeyRef from raw key data.
     *
     * @param keyData The raw key bytes (PKCS1 for RSA, raw point for EC public, etc.)
     * @param keyType kSecAttrKeyTypeRSA or kSecAttrKeyTypeECSECPrimeRandom
     * @param keyClass kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate
     * @param keySizeInBits The key size in bits
     */
    fun createSecKey(
        keyData: ByteArray,
        keyType: CFStringRef?,
        keyClass: CFStringRef?,
        keySizeInBits: Int
    ): SecKeyRef {
        memScoped {
            val cfData = keyData.toCFData(this)
            val attrs = createAttributes(keyType, keyClass, keySizeInBits, this)
            val error = alloc<CFErrorRefVar>()

            val secKey = SecKeyCreateWithData(cfData, attrs, error.ptr)
                ?: throw RuntimeException("Failed to create SecKey: ${describeError(error.value)}")

            CFRelease(attrs)
            CFRelease(cfData)
            return secKey
        }
    }

    /**
     * Generates a random key pair.
     *
     * @return Pair of (privateKeyRef, publicKeyRef)
     */
    fun generateKeyPair(
        keyType: CFStringRef?,
        keySizeInBits: Int
    ): Pair<SecKeyRef, SecKeyRef> {
        memScoped {
            val attrs = createKeyGenAttributes(keyType, keySizeInBits, this)
            val error = alloc<CFErrorRefVar>()

            val privateKey = SecKeyCreateRandomKey(attrs, error.ptr)
                ?: throw RuntimeException("Key generation failed: ${describeError(error.value)}")

            CFRelease(attrs)

            val publicKey = SecKeyCopyPublicKey(privateKey)
                ?: throw RuntimeException("Failed to extract public key")

            return privateKey to publicKey
        }
    }

    /**
     * Signs data with a SecKey.
     */
    fun sign(
        privateKey: SecKeyRef,
        algorithm: SecKeyAlgorithm?,
        data: ByteArray
    ): ByteArray {
        memScoped {
            val cfData = data.toCFData(this)
            val error = alloc<CFErrorRefVar>()

            val signature = SecKeyCreateSignature(privateKey, algorithm, cfData, error.ptr)
                ?: throw RuntimeException("Signing failed: ${describeError(error.value)}")

            CFRelease(cfData)

            val result = signature.toByteArray()
            CFRelease(signature)
            return result
        }
    }

    /**
     * Verifies a signature with a SecKey.
     */
    fun verify(
        publicKey: SecKeyRef,
        algorithm: SecKeyAlgorithm?,
        data: ByteArray,
        signature: ByteArray
    ): Boolean {
        memScoped {
            val cfData = data.toCFData(this)
            val cfSig = signature.toCFData(this)
            val error = alloc<CFErrorRefVar>()

            val result = SecKeyVerifySignature(publicKey, algorithm, cfData, cfSig, error.ptr)

            CFRelease(cfData)
            CFRelease(cfSig)
            return result
        }
    }

    /**
     * Exports the external representation of a SecKey.
     */
    fun exportKey(key: SecKeyRef): ByteArray {
        memScoped {
            val error = alloc<CFErrorRefVar>()
            val cfData = SecKeyCopyExternalRepresentation(key, error.ptr)
                ?: throw RuntimeException("Failed to export key: ${describeError(error.value)}")
            val result = cfData.toByteArray()
            CFRelease(cfData)
            return result
        }
    }

    // --- Internal helpers ---

    private fun createAttributes(
        keyType: CFStringRef?,
        keyClass: CFStringRef?,
        keySizeInBits: Int,
        scope: MemScope
    ): CFDictionaryRef {
        with(scope) {
            val dict = CFDictionaryCreateMutable(null, 3, null, null)!!
            CFDictionarySetValue(dict, kSecAttrKeyType, keyType)
            CFDictionarySetValue(dict, kSecAttrKeyClass, keyClass)
            val cfNumber = CFNumberCreate(
                null,
                kCFNumberSInt32Type,
                alloc<IntVar> { value = keySizeInBits }.ptr
            )
            CFDictionarySetValue(dict, kSecAttrKeySizeInBits, cfNumber)
            CFRelease(cfNumber)
            return dict
        }
    }

    private fun createKeyGenAttributes(
        keyType: CFStringRef?,
        keySizeInBits: Int,
        scope: MemScope
    ): CFDictionaryRef {
        with(scope) {
            val dict = CFDictionaryCreateMutable(null, 2, null, null)!!
            CFDictionarySetValue(dict, kSecAttrKeyType, keyType)
            val cfNumber = CFNumberCreate(
                null,
                kCFNumberSInt32Type,
                alloc<IntVar> { value = keySizeInBits }.ptr
            )
            CFDictionarySetValue(dict, kSecAttrKeySizeInBits, cfNumber)
            CFRelease(cfNumber)
            return dict
        }
    }

    private fun describeError(error: CFErrorRef?): String {
        if (error == null) return "unknown error"
        val desc = CFErrorCopyDescription(error)
        val result = desc?.toString() ?: "unknown error"
        if (desc != null) CFRelease(desc)
        return result
    }
}

// --- Extension helpers ---

@OptIn(ExperimentalForeignApi::class)
internal fun ByteArray.toCFData(scope: MemScope): CFDataRef {
    if (isEmpty()) return CFDataCreate(null, null, 0)!!
    return usePinned { pinned ->
        CFDataCreate(null, pinned.addressOf(0).reinterpret(), size.toLong())!!
    }
}

@OptIn(ExperimentalForeignApi::class)
internal fun CFDataRef.toByteArray(): ByteArray {
    val length = CFDataGetLength(this).toInt()
    if (length == 0) return ByteArray(0)
    val bytes = ByteArray(length)
    val ptr = CFDataGetBytePtr(this)
    bytes.usePinned { pinned ->
        platform.posix.memcpy(pinned.addressOf(0), ptr, length.toULong())
    }
    return bytes
}
