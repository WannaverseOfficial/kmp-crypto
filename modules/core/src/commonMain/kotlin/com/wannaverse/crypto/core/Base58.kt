package com.wannaverse.crypto.core

/**
 * Utility object for Base58 encoding and decoding.
 *
 * Base58 is commonly used in cryptocurrency addresses (e.g., Bitcoin) to represent binary data in a
 * compact and human-friendly format that avoids visually ambiguous characters.
 */
object Base58 {
    private const val BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    /**
     * Encodes the given byte array into a Base58 string.
     *
     * Leading zero bytes are encoded as '1' characters in the resulting string.
     *
     * @param bytes The binary data to encode.
     * @return The Base58-encoded string.
     */
    fun toBase58(bytes: ByteArray): String {
        val zeros = bytes.takeWhile { it == 0.toByte() }.count()
        val num = bytes.fold(0) { acc, byte ->
            acc * 256 + (byte.toInt() and 0xFF)
        }
        val result = mutableListOf<Char>()
        var temp = num
        while (temp > 0) {
            val index = (temp % 58).toInt()
            result.add(BASE58_ALPHABET[index])
            temp /= 58
        }
        return "1".repeat(zeros) + result.reversed().joinToString("")
    }

    /**
     * Decodes a Base58-encoded string back into a byte array.
     *
     * Leading '1' characters are converted to leading zero bytes in the output.
     *
     * @param base58 The Base58 string to decode.
     * @return The decoded byte array.
     * @throws IllegalArgumentException If the input contains characters not in the Base58 alphabet.
     */
    fun fromBase58(base58: String): ByteArray {
        val zeros = base58.takeWhile { it == '1' }.count()
        val num = base58.drop(zeros).fold(0) { acc, char ->
            val index = BASE58_ALPHABET.indexOf(char)
            require(index >= 0) { "Invalid Base58 character: $char" }
            acc * 58 + index
        }
        val byteList = mutableListOf<Byte>()
        var temp = num
        while (temp > 0) {
            byteList.add((temp % 256).toByte())
            temp /= 256
        }
        return ByteArray(zeros) { 0.toByte() } + byteList.reversed().toByteArray()
    }
}