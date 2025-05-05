package com.wannaverse.crypto.asymmetric.ed25519

/**
 * A data class representing an Ed25519 key pair.
 *
 * @property publicKey The Ed25519 public key, used for verifying digital signatures, represented as a byte array.
 * @property privateKey The Ed25519 private key, used for creating digital signatures, represented as a byte array.
 */
data class ED25519KeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray
)
