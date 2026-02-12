@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.wannaverse.crypto.asymmetric.ed25519

import com.wannaverse.crypto.asymmetric.util.DerUtils
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

actual object ED25519 {

    actual fun generateKeyPair(): ED25519KeyPair {
        // Generate a random 32-byte seed
        val seed = secureRandomBytes(32)

        // Derive public key from seed using pure Kotlin Ed25519
        val rawPublicKey = Ed25519Internals.generatePublicKey(seed)

        // Wrap in standard formats for cross-platform compatibility
        val x509Public = DerUtils.wrapEd25519PublicKey(rawPublicKey)
        val pkcs8Private = DerUtils.wrapEd25519PrivateKey(seed)

        return ED25519KeyPair(
            publicKey = x509Public,
            privateKey = pkcs8Private
        )
    }

    actual fun sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        // Extract the raw 32-byte seed from PKCS8
        val seed = DerUtils.stripEd25519PrivateKey(privateKey)
        return Ed25519Internals.sign(seed, data)
    }

    actual fun verify(publicKey: ByteArray, data: ByteArray, signatureBytes: ByteArray): Boolean {
        // Extract raw 32-byte public key from X.509
        val rawPublicKey = DerUtils.stripX509Header(publicKey)
        return Ed25519Internals.verify(rawPublicKey, data, signatureBytes)
    }

    private fun secureRandomBytes(length: Int): ByteArray {
        val result = ByteArray(length)
        result.usePinned {
            val status = SecRandomCopyBytes(kSecRandomDefault, length.toULong(), it.addressOf(0))
            if (status != 0) {
                throw RuntimeException("Failed to generate secure random bytes: $status")
            }
        }
        return result
    }
}
