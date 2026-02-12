package com.wannaverse.crypto.asymmetric.ecdsa

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

actual object ECDSA {
    actual fun generateKeyPair(curve: ECDSACurve): ECDSAKeyPair {
        val keyGen = KeyPairGenerator.getInstance("EC")
        keyGen.initialize(ECGenParameterSpec(curve.curveName))
        val keyPair = keyGen.generateKeyPair()
        return ECDSAKeyPair(
            publicKey = keyPair.public.encoded,
            privateKey = keyPair.private.encoded,
            curve = curve
        )
    }

    actual fun sign(privateKey: ByteArray, data: ByteArray, curve: ECDSACurve): ByteArray {
        val keyFactory = KeyFactory.getInstance("EC")
        val privKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKey)) as ECPrivateKey

        val sig = Signature.getInstance(signatureAlgorithm(curve))
        sig.initSign(privKey)
        sig.update(data)
        return sig.sign()
    }

    actual fun verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray, curve: ECDSACurve): Boolean {
        val keyFactory = KeyFactory.getInstance("EC")
        val pubKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKey)) as ECPublicKey

        val sig = Signature.getInstance(signatureAlgorithm(curve))
        sig.initVerify(pubKey)
        sig.update(data)
        return sig.verify(signature)
    }

    private fun signatureAlgorithm(curve: ECDSACurve): String = when (curve) {
        ECDSACurve.P256 -> "SHA256withECDSA"
        ECDSACurve.P384 -> "SHA384withECDSA"
        ECDSACurve.P521 -> "SHA512withECDSA"
    }
}
