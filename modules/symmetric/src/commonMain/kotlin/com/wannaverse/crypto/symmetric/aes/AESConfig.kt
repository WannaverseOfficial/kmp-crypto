package com.wannaverse.crypto.symmetric.aes

/**
 * Configuration class for AES encryption settings.
 *
 * This class holds the configuration parameters necessary to perform AES encryption or decryption.
 * The configuration allows setting various AES modes, key sizes, initialization vectors (IV),
 * additional authenticated data (AAD), and tag length (for GCM mode). These settings control the
 * behavior and security of AES operations.
 *
 * @property mode The AES cipher mode to be used (default is [AESMode.GCM]).
 * @property keySize The size of the AES key (default is [KeySize.AES_256]).
 * @property iv The initialization vector (IV) used in some AES modes (default is `null`).
 *               Used in modes like CBC, CFB, and OFB, and must be a securely generated random value.
 * @property aad Additional Authenticated Data (AAD) used in [AESMode.GCM] mode (default is `null`).
 *               This data is not encrypted but is authenticated as part of the GCM operation.
 * @property tagLength The length of the authentication tag in bits for [AESMode.GCM] (default is 128).
 *                      Valid tag lengths for GCM are typically 96, 104, 112, 120, and 128 bits.
 */
data class AESConfig(
    val mode: AESMode = AESMode.GCM,
    val keySize: KeySize = KeySize.AES_256,
    val iv: ByteArray? = null,
    val aad: ByteArray? = null, // Additional Authenticated Data for GCM
    val tagLength: Int = 128 // Tag length in bits for GCM (96, 104, 112, 120, 128)
)
