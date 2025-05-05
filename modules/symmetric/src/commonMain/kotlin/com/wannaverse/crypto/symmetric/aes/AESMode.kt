package com.wannaverse.crypto.symmetric.aes

/**
 * Enum class representing the different modes of AES cipher used in various encryption schemes.
 *
 * Each mode corresponds to a specific configuration of AES encryption, including
 * the padding scheme and encryption type. The modes in this enum can be used to
 * specify the cipher mode when performing encryption or decryption with AES.
 *
 * @property cipherMode The string representation of the AES cipher mode and padding scheme.
 *
 * Supported modes:
 * - [ECB] (Electronic Codebook): The plaintext is divided into blocks, and each block
 *   is independently encrypted. It is the simplest but least secure mode due to patterns
 *   in plaintext being reflected in ciphertext.
 * - [CBC] (Cipher Block Chaining): Each plaintext block is XORed with the previous ciphertext block
 *   before encryption, providing more security than ECB. A random initialization vector (IV) is used.
 * - [CFB] (Cipher Feedback): Similar to CBC but works on smaller units of data, offering stream cipher-like
 *   behavior with block cipher security.
 * - [OFB] (Output Feedback): Converts the block cipher into a stream cipher, using the previous cipher
 *   block to encrypt the next one.
 * - [CTR] (Counter): Turns AES into a stream cipher by combining a counter with an encryption key.
 * - [GCM] (Galois/Counter Mode): A mode that provides both confidentiality (encryption) and integrity
 *   (authentication) of data, using a counter and an authentication tag.
 */
enum class AESMode(val cipherMode: String) {
    /** AES in ECB mode with PKCS5 padding */
    ECB("AES/ECB/PKCS5Padding"),

    /** AES in CBC mode with PKCS5 padding */
    CBC("AES/CBC/PKCS5Padding"),

    /** AES in CFB mode with no padding */
    CFB("AES/CFB/NoPadding"),

    /** AES in OFB mode with no padding */
    OFB("AES/OFB/NoPadding"),

    /** AES in CTR mode with no padding */
    CTR("AES/CTR/NoPadding"),

    /** AES in GCM mode with no padding */
    GCM("AES/GCM/NoPadding")
}
