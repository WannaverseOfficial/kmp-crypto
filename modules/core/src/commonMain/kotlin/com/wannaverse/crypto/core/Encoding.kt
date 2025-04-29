package com.wannaverse.crypto.core

object Encoding {
    fun toHex(bytes: ByteArray): String =
        bytes.joinToString("") { it.toUByte().toString(16).padStart(2, '0') }

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

    fun toUtf8(text: String): ByteArray = text.encodeToByteArray()

    fun fromUtf8(bytes: ByteArray): String = bytes.decodeToString()

    fun toAscii(text: String): ByteArray {
        require(text.all { it.code in 0..127 }) { "Input contains non-ASCII characters" }
        return text.encodeToByteArray()
    }

    fun fromAscii(bytes: ByteArray): String {
        require(bytes.all { it.toInt() in 0..127 }) { "Input contains non-ASCII bytes" }
        return bytes.decodeToString()
    }

    fun intToBytes(value: Int, bigEndian: Boolean = true): ByteArray {
        val bytes = ByteArray(4) { ((value shr (it * 8)) and 0xFF).toByte() }
        return if (bigEndian) bytes.reversedArray() else bytes
    }

    fun longToBytes(value: Long, bigEndian: Boolean = true): ByteArray {
        val bytes = ByteArray(8) { ((value shr (it * 8)) and 0xFFL).toByte() }
        return if (bigEndian) bytes.reversedArray() else bytes
    }

    fun bytesToInt(bytes: ByteArray, bigEndian: Boolean = true): Int {
        require(bytes.size <= 4) { "Byte array too large for Int" }
        val padded = ByteArray(4) { if (it < 4 - bytes.size) 0 else bytes[it - (4 - bytes.size)] }
        return padded.fold(0) { acc, byte ->
            (acc shl 8) or (byte.toInt() and 0xFF)
        }
    }

    fun bytesToLong(bytes: ByteArray, bigEndian: Boolean = true): Long {
        require(bytes.size <= 8) { "Byte array too large for Long" }
        val padded = ByteArray(8) { if (it < 8 - bytes.size) 0 else bytes[it - (8 - bytes.size)] }
        return padded.fold(0L) { acc, byte ->
            (acc shl 8) or (byte.toLong() and 0xFF)
        }
    }

    fun pkcs7Pad(bytes: ByteArray, blockSize: Int): ByteArray {
        require(blockSize in 1..255) { "Invalid block size" }
        val paddingLength = blockSize - (bytes.size % blockSize)
        return bytes + ByteArray(paddingLength) { paddingLength.toByte() }
    }

    fun pkcs7Unpad(bytes: ByteArray): ByteArray {
        require(bytes.isNotEmpty()) { "Input is empty" }
        val paddingLength = bytes.last().toInt() and 0xFF
        require(paddingLength in 1..bytes.size && bytes.takeLast(paddingLength).all { it == paddingLength.toByte() }) {
            "Invalid PKCS#7 padding"
        }
        return bytes.dropLast(paddingLength).toByteArray()
    }
}