package com.wannaverse.crypto.asymmetric.ed25519

actual class ED25519 {
    actual fun generateKeyPair(): ED25519KeyPair {
        TODO("Not yet implemented")
    }

    actual fun sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        TODO("Not yet implemented")
    }

    actual fun verify(
        publicKey: ByteArray,
        data: ByteArray,
        signatureBytes: ByteArray
    ): Boolean {
        TODO("Not yet implemented")
    }

}