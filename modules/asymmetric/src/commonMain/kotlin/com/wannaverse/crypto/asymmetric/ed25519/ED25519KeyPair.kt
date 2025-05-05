package com.wannaverse.crypto.asymmetric.ed25519

data class ED25519KeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray
)