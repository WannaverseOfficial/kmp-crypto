package com.wannaverse.crypto.asymmetric.rsa

/**
 * A data class representing a pair of RSA keys: public and private.
 *
 * @property publicKey The RSA public key, used for encryption and signature verification, represented as a byte array.
 * @property privateKey The RSA private key, used for decryption and signing, represented as a byte array.
 */
data class RSAKeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray
)