package com.wannaverse.crypto.asymmetric.ed25519

expect class ED25519 {
    fun generateKeyPair(): ED25519KeyPair

    fun sign(privateKey: ByteArray, data: ByteArray): ByteArray

    fun verify(publicKey: ByteArray, data: ByteArray, signatureBytes: ByteArray): Boolean
}