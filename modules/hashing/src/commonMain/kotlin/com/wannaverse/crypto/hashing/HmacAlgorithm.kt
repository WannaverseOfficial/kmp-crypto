package com.wannaverse.crypto.hashing

/**
 * Enum representing supported HMAC algorithms.
 *
 * @property algorithmName The JCA algorithm name used by cryptographic providers.
 * @property digestLength The output length of the HMAC in bytes.
 */
enum class HmacAlgorithm(val algorithmName: String, val digestLength: Int) {
    HMAC_SHA256("HmacSHA256", 32),
    HMAC_SHA384("HmacSHA384", 48),
    HMAC_SHA512("HmacSHA512", 64)
}
