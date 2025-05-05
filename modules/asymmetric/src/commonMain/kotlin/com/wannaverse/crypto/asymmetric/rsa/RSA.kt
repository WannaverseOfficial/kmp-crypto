package com.wannaverse.crypto.asymmetric.rsa

/**
 * An expect class representing RSA cryptographic operations.
 * The actual implementation should be provided in platform-specific code.
 */
expect object RSA {
    /**
     * Generates an RSA key pair with the specified key size.
     *
     * @param keySize The size of the RSA key in bits. Defaults to 2048.
     * @return An [RSAKeyPair] containing the generated public and private keys.
     */
    fun generateKeyPair(keySize: Int = 2048): RSAKeyPair

    /**
     * Encrypts the given data using the provided RSA public key and padding scheme.
     *
     * @param publicKey The public key to use for encryption, in byte array format.
     * @param data The data to encrypt, as a byte array.
     * @param padding The padding scheme to use. Defaults to [RSAPadding.PKCS1].
     * @return The encrypted data as a byte array.
     */
    fun encrypt(
        publicKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding = RSAPadding.PKCS1
    ): ByteArray

    /**
     * Decrypts the given data using the provided RSA private key and padding scheme.
     *
     * @param privateKey The private key to use for decryption, in byte array format.
     * @param data The encrypted data to decrypt, as a byte array.
     * @param padding The padding scheme used during encryption. Defaults to [RSAPadding.PKCS1].
     * @return The decrypted data as a byte array.
     */
    fun decrypt(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSAPadding = RSAPadding.PKCS1
    ): ByteArray

    /**
     * Verifies a digital signature using the provided RSA public key and padding scheme.
     *
     * @param publicKey The public key to use for verification, in byte array format.
     * @param signature The signature to verify, as a byte array.
     * @param data The original data that was signed, as a byte array.
     * @param padding The signature padding scheme used. Defaults to [RSASignaturePadding.PKCS1_SHA256].
     * @return `true` if the signature is valid, `false` otherwise.
     */
    fun verify(
        publicKey: ByteArray,
        signature: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding = RSASignaturePadding.PKCS1_SHA256
    ): Boolean

    /**
     * Creates a digital signature for the given data using the provided RSA private key and padding scheme.
     *
     * @param privateKey The private key to use for signing, in byte array format.
     * @param data The data to sign, as a byte array.
     * @param padding The signature padding scheme to use.
     * @return The generated signature as a byte array.
     */
    fun sign(
        privateKey: ByteArray,
        data: ByteArray,
        padding: RSASignaturePadding
    ): ByteArray
}