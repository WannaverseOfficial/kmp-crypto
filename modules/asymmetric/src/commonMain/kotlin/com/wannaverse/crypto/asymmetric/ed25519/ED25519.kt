package com.wannaverse.crypto.asymmetric.ed25519

/**
 * An expect class representing Ed25519 cryptographic operations.
 * The actual implementations should be provided in platform-specific source sets.
 */
expect object ED25519 {

    /**
     * Generates a new Ed25519 key pair.
     *
     * @return An [ED25519KeyPair] containing the generated public and private keys.
     */
    fun generateKeyPair(): ED25519KeyPair

    /**
     * Signs the given data using the provided Ed25519 private key.
     *
     * @param privateKey The private key used to sign the data, as a byte array.
     * @param data The data to sign, as a byte array.
     * @return The signature as a byte array.
     */
    fun sign(privateKey: ByteArray, data: ByteArray): ByteArray

    /**
     * Verifies a signature using the provided Ed25519 public key.
     *
     * @param publicKey The public key used to verify the signature, as a byte array.
     * @param data The original data that was signed, as a byte array.
     * @param signatureBytes The signature to verify, as a byte array.
     * @return `true` if the signature is valid, `false` otherwise.
     */
    fun verify(publicKey: ByteArray, data: ByteArray, signatureBytes: ByteArray): Boolean
}
