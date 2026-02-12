package com.wannaverse.crypto.asymmetric.ecdsa

/**
 * Represents an ECDSA key pair.
 *
 * @property publicKey The public key in X.509 encoded format.
 * @property privateKey The private key in PKCS#8 encoded format.
 * @property curve The elliptic curve used for this key pair.
 */
data class ECDSAKeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray,
    val curve: ECDSACurve
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ECDSAKeyPair) return false
        return publicKey.contentEquals(other.publicKey) &&
                privateKey.contentEquals(other.privateKey) &&
                curve == other.curve
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + curve.hashCode()
        return result
    }
}
