package com.wannaverse.crypto.core

/**
 * Utility object for encoding and decoding operations, as well as padding and unpadding byte arrays.
 * This object provides functions to convert between different formats like hexadecimal, UTF-8, ASCII,
 * and to handle byte array operations like padding and conversion to/from integers and longs.
 */
object Encoding {

    /**
     * Converts a byte array to a hexadecimal string representation.
     *
     * @param bytes The byte array to convert.
     * @return A hexadecimal string representing the input byte array.
     */
    fun toHex(bytes: ByteArray): String =
        bytes.joinToString("") { it.toUByte().toString(16).padStart(2, '0') }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * The string may optionally start with `0x`, which will be removed before processing.
     * Ensures that the length of the hexadecimal string is even and contains only valid hexadecimal characters.
     *
     * @param hex The hexadecimal string to convert.
     * @return A byte array representation of the hexadecimal string.
     * @throws IllegalArgumentException if the hex string has an invalid length or contains invalid characters.
     */
    fun fromHex(hex: String): ByteArray {
        val cleanHex = hex.removePrefix("0x").lowercase()
        require(cleanHex.length % 2 == 0) { "Hex string must have even length" }
        require(cleanHex.all { it in '0'..'9' || it in 'a'..'f' }) {
            "Hex string contains invalid characters"
        }
        return cleanHex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }

    /**
     * Converts a string to a UTF-8 byte array.
     *
     * @param text The string to convert.
     * @return A byte array representing the UTF-8 encoding of the string.
     */
    fun toUtf8(text: String): ByteArray = text.encodeToByteArray()

    /**
     * Converts a UTF-8 byte array back to a string.
     *
     * @param bytes The byte array to convert.
     * @return The string representation of the UTF-8 byte array.
     */
    fun fromUtf8(bytes: ByteArray): String = bytes.decodeToString()

    /**
     * Converts a string to an ASCII byte array.
     *
     * @param text The string to convert.
     * @return A byte array representing the ASCII encoding of the string.
     * @throws IllegalArgumentException if the string contains non-ASCII characters.
     */
    fun toAscii(text: String): ByteArray {
        require(text.all { it.code in 0..127 }) { "Input contains non-ASCII characters" }
        return text.encodeToByteArray()
    }

    /**
     * Converts an ASCII byte array back to a string.
     *
     * @param bytes The byte array to convert.
     * @return The string representation of the ASCII byte array.
     * @throws IllegalArgumentException if the byte array contains non-ASCII bytes.
     */
    fun fromAscii(bytes: ByteArray): String {
        require(bytes.all { it.toInt() in 0..127 }) { "Input contains non-ASCII bytes" }
        return bytes.decodeToString()
    }

    /**
     * Converts an integer to a byte array.
     *
     * @param value The integer to convert.
     * @param bigEndian If `true`, the byte array will be in big-endian order, otherwise little-endian.
     * @return A byte array representing the integer.
     */
    fun intToBytes(value: Int, bigEndian: Boolean = true): ByteArray {
        val bytes = ByteArray(4) { ((value shr (it * 8)) and 0xFF).toByte() }
        return if (bigEndian) bytes.reversedArray() else bytes
    }

    /**
     * Converts a long to a byte array.
     *
     * @param value The long to convert.
     * @param bigEndian If `true`, the byte array will be in big-endian order, otherwise little-endian.
     * @return A byte array representing the long.
     */
    fun longToBytes(value: Long, bigEndian: Boolean = true): ByteArray {
        val bytes = ByteArray(8) { ((value shr (it * 8)) and 0xFFL).toByte() }
        return if (bigEndian) bytes.reversedArray() else bytes
    }

    /**
     * Converts a byte array to an integer.
     *
     * The byte array should be no longer than 4 bytes.
     *
     * @param bytes The byte array to convert.
     * @param bigEndian If `true`, the byte array is interpreted as big-endian, otherwise little-endian.
     * @return The integer representation of the byte array.
     * @throws IllegalArgumentException if the byte array is too large to fit in an integer.
     */
    fun bytesToInt(bytes: ByteArray, bigEndian: Boolean = true): Int {
        require(bytes.size <= 4) { "Byte array too large for Int" }
        val padded = ByteArray(4) { if (it < 4 - bytes.size) 0 else bytes[it - (4 - bytes.size)] }
        return padded.fold(0) { acc, byte ->
            (acc shl 8) or (byte.toInt() and 0xFF)
        }
    }

    /**
     * Converts a byte array to a long.
     *
     * The byte array should be no longer than 8 bytes.
     *
     * @param bytes The byte array to convert.
     * @param bigEndian If `true`, the byte array is interpreted as big-endian, otherwise little-endian.
     * @return The long representation of the byte array.
     * @throws IllegalArgumentException if the byte array is too large to fit in a long.
     */
    fun bytesToLong(bytes: ByteArray, bigEndian: Boolean = true): Long {
        require(bytes.size <= 8) { "Byte array too large for Long" }
        val padded = ByteArray(8) { if (it < 8 - bytes.size) 0 else bytes[it - (8 - bytes.size)] }
        return padded.fold(0L) { acc, byte ->
            (acc shl 8) or (byte.toLong() and 0xFF)
        }
    }

    /**
     * Applies PKCS#7 padding to a byte array.
     *
     * PKCS#7 padding ensures that the byte array's length is a multiple of the specified block size.
     * The padding value is the number of bytes added.
     *
     * @param bytes The byte array to pad.
     * @param blockSize The block size to pad the array to.
     * @return A new byte array with PKCS#7 padding applied.
     * @throws IllegalArgumentException if the block size is invalid.
     */
    fun pkcs7Pad(bytes: ByteArray, blockSize: Int): ByteArray {
        require(blockSize in 1..255) { "Invalid block size" }
        val paddingLength = blockSize - (bytes.size % blockSize)
        return bytes + ByteArray(paddingLength) { paddingLength.toByte() }
    }

    /**
     * Removes PKCS#7 padding from a byte array.
     *
     * @param bytes The padded byte array to unpad.
     * @return A new byte array with PKCS#7 padding removed.
     * @throws IllegalArgumentException if the padding is invalid.
     */
    fun pkcs7Unpad(bytes: ByteArray): ByteArray {
        require(bytes.isNotEmpty()) { "Input is empty" }
        val paddingLength = bytes.last().toInt() and 0xFF
        require(paddingLength in 1..bytes.size && bytes.takeLast(paddingLength).all { it == paddingLength.toByte() }) {
            "Invalid PKCS#7 padding"
        }
        return bytes.dropLast(paddingLength).toByteArray()
    }
}
