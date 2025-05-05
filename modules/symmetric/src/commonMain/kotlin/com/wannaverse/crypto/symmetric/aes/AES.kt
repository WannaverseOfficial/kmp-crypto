package com.wannaverse.crypto.symmetric.aes

/**
 * Expect class that provides AES encryption and decryption functionality.
 *
 * This class allows for the encryption and decryption of data using the Advanced Encryption Standard (AES).
 * It supports various AES modes (such as GCM, CBC, etc.), key sizes (128, 192, 256 bits),
 * and includes configurations for initialization vectors (IV), additional authenticated data (AAD),
 * and tag lengths (for GCM mode).
 *
 * The class provides methods for encrypting and decrypting data, as well as generating keys of
 * different sizes for AES operations.
 */
expect class AES() {

    /**
     * Encrypts the given plaintext using the specified key and configuration.
     *
     * @param plaintext The data to be encrypted.
     * @param key The key to use for encryption.
     * @param config The configuration to use for encryption (default is [AESConfig()]).
     *               This includes mode, key size, IV, AAD, and tag length (for GCM).
     * @return The encrypted ciphertext as a byte array.
     */
    fun encrypt(plaintext: ByteArray, key: ByteArray, config: AESConfig = AESConfig()): ByteArray

    /**
     * Decrypts the given ciphertext using the specified key and configuration.
     *
     * @param ciphertext The data to be decrypted.
     * @param key The key to use for decryption.
     * @param config The configuration to use for decryption (default is [AESConfig()]).
     *               This includes mode, key size, IV, AAD, and tag length (for GCM).
     * @return The decrypted plaintext as a byte array.
     */
    fun decrypt(ciphertext: ByteArray, key: ByteArray, config: AESConfig = AESConfig()): ByteArray

    /**
     * Generates a random AES key of the specified size.
     *
     * @param keySize The key size to generate (default is [KeySize.AES_256]).
     *                This can be [KeySize.AES_128], [KeySize.AES_192], or [KeySize.AES_256].
     * @return A byte array representing the generated key.
     */
    fun createKey(keySize: KeySize = KeySize.AES_256): ByteArray
}
