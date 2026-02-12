package com.wannaverse.crypto.asymmetric.ecdsa

/**
 * Provides ECDSA (Elliptic Curve Digital Signature Algorithm) operations.
 *
 * Supports P-256, P-384, and P-521 curves. Signatures are produced in DER encoding.
 */
expect object ECDSA {
    /**
     * Generates an ECDSA key pair for the specified curve.
     *
     * @param curve The elliptic curve to use. Defaults to [ECDSACurve.P256].
     * @return An [ECDSAKeyPair] containing the generated public and private keys.
     */
    fun generateKeyPair(curve: ECDSACurve = ECDSACurve.P256): ECDSAKeyPair

    /**
     * Signs the given data using the provided ECDSA private key.
     *
     * The hash algorithm is determined by the curve: SHA-256 for P-256, SHA-384 for P-384, SHA-512 for P-521.
     *
     * @param privateKey The private key in PKCS#8 encoded format.
     * @param data The data to sign as a byte array.
     * @param curve The elliptic curve used. Defaults to [ECDSACurve.P256].
     * @return The DER-encoded signature as a byte array.
     */
    fun sign(privateKey: ByteArray, data: ByteArray, curve: ECDSACurve = ECDSACurve.P256): ByteArray

    /**
     * Verifies a DER-encoded signature using the provided ECDSA public key.
     *
     * @param publicKey The public key in X.509 encoded format.
     * @param data The original data that was signed.
     * @param signature The DER-encoded signature to verify.
     * @param curve The elliptic curve used. Defaults to [ECDSACurve.P256].
     * @return `true` if the signature is valid, `false` otherwise.
     */
    fun verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray, curve: ECDSACurve = ECDSACurve.P256): Boolean
}
