package com.wannaverse.crypto.asymmetric.ed25519

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

actual object ED25519 {

    // PKCS8 DER prefix for Ed25519 private key (RFC 8410)
    private val PKCS8_PREFIX = byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    )

    // X509/SPKI DER prefix for Ed25519 public key (RFC 8410)
    private val X509_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
        0x70, 0x03, 0x21, 0x00
    )

    @OptIn(ExperimentalForeignApi::class)
    actual fun generateKeyPair(): ED25519KeyPair {
        val seed = ByteArray(32)
        seed.usePinned {
            val status = SecRandomCopyBytes(kSecRandomDefault, 32u, it.addressOf(0))
            if (status != 0) {
                throw IllegalStateException("Failed to generate secure random bytes")
            }
        }

        val rawPublicKey = Ed25519Internals.generatePublicKey(seed)

        return ED25519KeyPair(
            publicKey = X509_PREFIX + rawPublicKey,
            privateKey = PKCS8_PREFIX + seed
        )
    }

    actual fun sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        val seed = extractPrivateKey(privateKey)
        return Ed25519Internals.sign(seed, data)
    }

    actual fun verify(publicKey: ByteArray, data: ByteArray, signatureBytes: ByteArray): Boolean {
        val rawPublicKey = extractPublicKey(publicKey)
        return Ed25519Internals.verify(rawPublicKey, data, signatureBytes)
    }

    private fun extractPrivateKey(encoded: ByteArray): ByteArray {
        require(encoded.size == PKCS8_PREFIX.size + 32) {
            "Invalid PKCS8 Ed25519 private key length: ${encoded.size}"
        }
        return encoded.copyOfRange(PKCS8_PREFIX.size, encoded.size)
    }

    private fun extractPublicKey(encoded: ByteArray): ByteArray {
        require(encoded.size == X509_PREFIX.size + 32) {
            "Invalid X509 Ed25519 public key length: ${encoded.size}"
        }
        return encoded.copyOfRange(X509_PREFIX.size, encoded.size)
    }
}
