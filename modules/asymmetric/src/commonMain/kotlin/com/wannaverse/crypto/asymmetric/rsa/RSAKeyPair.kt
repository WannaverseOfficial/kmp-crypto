package com.wannaverse.crypto.asymmetric.rsa

data class RSAKeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray
)