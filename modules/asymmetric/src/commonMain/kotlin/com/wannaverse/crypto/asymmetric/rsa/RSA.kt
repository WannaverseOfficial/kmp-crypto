package com.wannaverse.crypto.asymmetric.rsa

expect class RSA {
    fun generateKeyPair(keySize: Int = 2048): RSAKeyPair

    fun encrypt(
        publicKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding = RSAPadding.PKCS1
    ): ByteArray

    fun decrypt(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding = RSAPadding.PKCS1
    ): ByteArray

    fun verify(
        publicKey: ByteArray,
        signature: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding = RSASignaturePadding.PKCS1_SHA256
    ): Boolean

    fun sign(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding
    ): ByteArray
}