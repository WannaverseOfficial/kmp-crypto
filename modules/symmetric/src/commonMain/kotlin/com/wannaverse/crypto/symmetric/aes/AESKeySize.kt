package com.wannaverse.crypto.symmetric.aes

/**
 * Enum class representing the different key sizes supported for AES.
 *
 * AES supports various key sizes, which determine the strength of the encryption. The key size
 * is an important factor in determining the level of security provided by AES encryption.
 *
 * @property bits The number of bits in the AES key for the corresponding key size.
 *
 * Supported key sizes:
 * - [AES_128] (128 bits): The smallest supported key size, offering a good level of security for many use cases.
 * - [AES_192] (192 bits): A medium-strength key size, providing enhanced security compared to AES-128.
 * - [AES_256] (256 bits): The highest supported key size, offering the strongest security and often used
 *   for highly sensitive data.
 */
enum class KeySize(val bits: Int) {
    /** AES key size with 128 bits */
    AES_128(128),

    /** AES key size with 192 bits */
    AES_192(192),

    /** AES key size with 256 bits */
    AES_256(256)
}
