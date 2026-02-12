package com.wannaverse.crypto.hashing

/**
 * Provides HMAC (Hash-based Message Authentication Code) operations.
 *
 * Supports HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512.
 */
expect object HMAC {
    /**
     * Computes the HMAC of the given data using the specified key and algorithm.
     *
     * @param key The secret key as a byte array.
     * @param data The data to authenticate as a byte array.
     * @param algorithm The HMAC algorithm to use. Defaults to [HmacAlgorithm.HMAC_SHA256].
     * @return The HMAC as a byte array.
     */
    fun sign(key: ByteArray, data: ByteArray, algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256): ByteArray

    /**
     * Verifies an HMAC signature using constant-time comparison.
     *
     * @param key The secret key as a byte array.
     * @param data The original data as a byte array.
     * @param signature The HMAC signature to verify as a byte array.
     * @param algorithm The HMAC algorithm to use. Defaults to [HmacAlgorithm.HMAC_SHA256].
     * @return `true` if the signature is valid, `false` otherwise.
     */
    fun verify(key: ByteArray, data: ByteArray, signature: ByteArray, algorithm: HmacAlgorithm = HmacAlgorithm.HMAC_SHA256): Boolean
}
