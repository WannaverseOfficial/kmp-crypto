package com.wannaverse.crypto.core

/**
 * Utility object for Base64 encoding and decoding.
 *
 * Supports both standard and URL-safe Base64 variants. This implementation does not include padding (`=`),
 * which is often optional in URL-safe formats but may be required for strict decoders.
 */
object Base64 {
    private const val BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    /**
     * Encodes the given byte array into a standard Base64 string.
     *
     * Note: This implementation does not append padding characters (`=`).
     *
     * @param bytes The binary data to encode.
     * @return The Base64-encoded string.
     */
    fun toBase64(bytes: ByteArray): String {
        val result = StringBuilder()
        for (i in bytes.indices step 3) {
            val b1 = bytes[i].toInt() and 0xFF
            val b2 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
            val b3 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
            result.append(BASE64_ALPHABET[b1 shr 2])
            result.append(BASE64_ALPHABET[(b1 shl 4 or (b2 shr 4)) and 0x3F])
            if (i + 1 < bytes.size) result.append(BASE64_ALPHABET[(b2 shl 2 or (b3 shr 6)) and 0x3F])
            if (i + 2 < bytes.size) result.append(BASE64_ALPHABET[b3 and 0x3F])
        }
        return result.toString()
    }

    /**
     * Encodes the given byte array into a URL-safe Base64 string.
     *
     * Replaces '+' with '-', '/' with '_', and strips trailing `=` padding characters.
     *
     * @param bytes The binary data to encode.
     * @return The URL-safe Base64-encoded string.
     */
    fun toBase64UrlSafe(bytes: ByteArray): String =
        toBase64(bytes).replace('+', '-').replace('/', '_').trimEnd('=')

    /**
     * Decodes a Base64-encoded string into a byte array.
     *
     * Accepts both standard and URL-safe Base64 variants (without padding).
     *
     * @param base64 The Base64 string to decode.
     * @return The decoded byte array.
     * @throws IllegalArgumentException If the string contains invalid Base64 characters.
     */
    fun fromBase64(base64: String): ByteArray {
        val cleanInput = base64.replace("[-_]", "+").replace("=", "")
        val result = mutableListOf<Byte>()
        var i = 0
        while (i < cleanInput.length) {
            val c1 = BASE64_ALPHABET.indexOf(cleanInput[i])
            val c2 = if (i + 1 < cleanInput.length) BASE64_ALPHABET.indexOf(cleanInput[i + 1]) else 0
            val c3 = if (i + 2 < cleanInput.length) BASE64_ALPHABET.indexOf(cleanInput[i + 2]) else 0
            val c4 = if (i + 3 < cleanInput.length) BASE64_ALPHABET.indexOf(cleanInput[i + 3]) else 0
            result.add((c1 shl 2 or (c2 shr 4)).toByte())
            if (i + 2 < cleanInput.length) result.add(((c2 shl 4) or (c3 shr 2)).toByte())
            if (i + 3 < cleanInput.length) result.add(((c3 shl 6) or c4).toByte())
            i += 4
        }
        return result.toByteArray()
    }
}