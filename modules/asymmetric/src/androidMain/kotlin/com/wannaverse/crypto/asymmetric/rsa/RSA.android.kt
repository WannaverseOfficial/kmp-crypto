package com.wannaverse.crypto.asymmetric.rsa

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

actual class RSA {
    actual fun generateKeyPair(keySize: Int): RSAKeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(keySize)

        val keyPair = keyGen.generateKeyPair()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey

        return RSAKeyPair(
            publicKey = publicKey.encoded,
            privateKey = privateKey.encoded,
        )
    }

    actual fun encrypt(
        publicKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding
    ): ByteArray {
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKeySpec = X509EncodedKeySpec(publicKey)
        val rsaPublicKey = keyFactory.generatePublic(publicKeySpec) as RSAPublicKey

        val cipher = Cipher.getInstance(padding.paddingString)
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey)
        return cipher.doFinal(data)
    }

    actual fun decrypt(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding
    ): ByteArray {
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKeySpec = PKCS8EncodedKeySpec(privateKey)
        val rsaPrivateKey = keyFactory.generatePrivate(privateKeySpec) as RSAPrivateKey

        val cipher = Cipher.getInstance(padding.paddingString)
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey)
        return cipher.doFinal(data)
    }

    actual fun verify(
        publicKey: ByteArray,
        signature: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding
    ): Boolean {
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKeySpec = X509EncodedKeySpec(publicKey)
        val rsaPublicKey = keyFactory.generatePublic(publicKeySpec) as RSAPublicKey

        val sig = Signature.getInstance(padding.signatureString)
        sig.initVerify(rsaPublicKey)
        sig.update(data)
        return sig.verify(signature)
    }

    actual fun sign(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding
    ): ByteArray {
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKeySpec = PKCS8EncodedKeySpec(privateKey)
        val rsaPrivateKey = keyFactory.generatePrivate(privateKeySpec) as RSAPrivateKey

        val sig = Signature.getInstance(padding.signatureString)
        sig.initSign(rsaPrivateKey)
        sig.update(data)
        return sig.sign()
    }
}