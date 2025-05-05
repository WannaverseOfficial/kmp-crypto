package com.wannaverse.crypto.asymmetric.rsa

actual object RSA {
    actual fun generateKeyPair(keySize: Int): RSAKeyPair {
        TODO("Not yet implemented")
    }

    actual fun encrypt(
        publicKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding
    ): ByteArray {
        TODO("Not yet implemented")
    }

    actual fun decrypt(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding
    ): ByteArray {
        TODO("Not yet implemented")
    }

    actual fun verify(
        publicKey: ByteArray,
        signature: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding
    ): Boolean {
        TODO("Not yet implemented")
    }

    actual fun sign(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding
    ): ByteArray {
        TODO("Not yet implemented")
    }

}