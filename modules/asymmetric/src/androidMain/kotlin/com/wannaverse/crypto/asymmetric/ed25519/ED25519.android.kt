package com.wannaverse.crypto.asymmetric.ed25519

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec

actual class ED25519 {
    actual fun generateKeyPair(): ED25519KeyPair {
        val keyGen = KeyPairGenerator.getInstance("Ed25519")
        val keyPair = keyGen.generateKeyPair()
        return ED25519KeyPair(
            publicKey = keyPair.public.encoded,
            privateKey = keyPair.private.encoded
        )
    }

    actual fun sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        val keyFactory = KeyFactory.getInstance("Ed25519")
        val privateSpec = PKCS8EncodedKeySpec(privateKey)
        val privKey = keyFactory.generatePrivate(privateSpec)

        val signature = Signature.getInstance("Ed25519")
        signature.initSign(privKey)
        signature.update(data)
        return signature.sign()
    }

    actual fun verify(publicKey: ByteArray, data: ByteArray, signatureBytes: ByteArray): Boolean {
        val keyFactory = KeyFactory.getInstance("Ed25519")
        val pubSpec = java.security.spec.X509EncodedKeySpec(publicKey)
        val pubKey = keyFactory.generatePublic(pubSpec)

        val signature = Signature.getInstance("Ed25519")
        signature.initVerify(pubKey)
        signature.update(data)
        return signature.verify(signatureBytes)
    }
}