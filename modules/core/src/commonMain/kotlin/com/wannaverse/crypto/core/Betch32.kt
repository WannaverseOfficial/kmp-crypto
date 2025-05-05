package com.wannaverse.crypto.core

/**
 * Utility class for Bech32 encoding and decoding.
 *
 * Bech32 is a checksummed base32 encoding used widely in blockchain addresses (e.g., Bitcoin SegWit).
 * This implementation follows the Bech32 specification for encoding/decoding with strong validation.
 */
class Betch32 {
    private val BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val BECH32_GENERATOR =
        intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)

    /**
     * Encodes the given HRP and 5-bit data into a Bech32 string.
     *
     * @param hrp The human-readable part (e.g., "bc" or "tb").
     * @param data A byte array of 5-bit values (each must be in range 0..31).
     * @return The Bech32-encoded string.
     * @throws IllegalArgumentException If input values are invalid or out of range.
     */
    fun toBech32(hrp: String, data: ByteArray): String {
        require(hrp.isNotEmpty() && hrp.length <= 83) { "HRP length must be 1-83 characters" }
        require(hrp.all { it.code in 33..126 && it != '1' }) { "Invalid HRP character" }
        require(data.all { it.toInt() in 0..31 }) { "Data contains values outside 0-31 range" }

        // Convert HRP to lowercase for consistency
        val hrpLower = hrp.lowercase()

        // Compute checksum
        val checksum = createBech32Checksum(hrpLower, data)

        // Combine data and checksum
        val combined = data + checksum

        // Build Bech32 string: HRP + separator + data + checksum
        val result = buildString {
            append(hrpLower)
            append('1')
            combined.forEach { append(BECH32_ALPHABET[it.toInt()]) }
        }

        return result
    }

    /**
     * Decodes a Bech32-encoded string into its HRP and original 5-bit data.
     *
     * @param bech32 The Bech32-encoded string.
     * @return A pair of [HRP, data] with checksum removed.
     * @throws IllegalArgumentException If the input is invalid or checksum fails.
     */
    fun fromBech32(bech32: String): Pair<String, ByteArray> {
        require(bech32.length >= 8 && bech32.length <= 90) {
            "Bech32 string length must be 8-90 characters"
        }
        require(bech32.contains('1')) { "Bech32 string must contain separator '1'" }

        // Split into HRP and data parts
        val separatorIndex = bech32.lastIndexOf('1')
        require(separatorIndex >= 1) { "HRP must be at least 1 character" }
        val hrp = bech32.substring(0, separatorIndex)
        val dataPart = bech32.substring(separatorIndex + 1)

        require(hrp.isNotEmpty() && hrp.length <= 83) { "HRP length must be 1-83 characters" }
        require(hrp.all { it.code in 33..126 }) { "Invalid HRP character" }
        require(dataPart.length >= 6) { "Data part too short (must include checksum)" }
        require(dataPart.all { it in BECH32_ALPHABET }) { "Invalid Bech32 character" }

        // Convert data part to 5-bit values
        val data =
            dataPart
                .map { char ->
                    val index = BECH32_ALPHABET.indexOf(char)
                    require(index >= 0) { "Invalid Bech32 character: $char" }
                    index.toByte()
                }
                .toByteArray()

        // Verify checksum
        require(verifyBech32Checksum(hrp.lowercase(), data)) { "Invalid Bech32 checksum" }

        // Return HRP and data (excluding 6-byte checksum)
        return hrp to data.dropLast(6).toByteArray()
    }


    fun convertTo5Bit(bytes: ByteArray): ByteArray {
        val result = mutableListOf<Byte>()
        var buffer = 0
        var bits = 0

        for (byte in bytes) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                result.add(((buffer shr (bits - 5)) and 0x1F).toByte())
                bits -= 5
            }
        }

        if (bits > 0) {
            result.add(((buffer shl (5 - bits)) and 0x1F).toByte())
        }

        return result.toByteArray()
    }

    /**
     * Converts a byte array to an array of 5-bit values, suitable for Bech32 encoding.
     *
     * @param bytes A standard byte array.
     * @return A 5-bit grouped byte array.
     */
    fun convertFrom5Bit(data: ByteArray): ByteArray {
        require(data.all { it.toInt() in 0..31 }) { "Data contains values outside 0-31 range" }

        val result = mutableListOf<Byte>()
        var buffer = 0
        var bits = 0

        for (value in data) {
            buffer = (buffer shl 5) or (value.toInt() and 0x1F)
            bits += 5
            while (bits >= 8) {
                result.add(((buffer shr (bits - 8)) and 0xFF).toByte())
                bits -= 8
            }
        }

        // Check for valid padding
        require(bits < 5) { "Invalid 5-bit data padding" }
        return result.toByteArray()
    }

    private fun createBech32Checksum(hrp: String, data: ByteArray): ByteArray {
        val values = hrpExpand(hrp) + data
        val polyMod = polyMod(values + ByteArray(6) { 0 }) xor 1
        val checksum = ByteArray(6)
        for (i in 0..5) {
            checksum[i] = ((polyMod shr (5 * (5 - i))) and 0x1F).toByte()
        }
        return checksum
    }

    private fun verifyBech32Checksum(hrp: String, data: ByteArray): Boolean {
        val values = hrpExpand(hrp) + data
        return polyMod(values) == 1
    }

    private fun hrpExpand(hrp: String): ByteArray {
        val result = mutableListOf<Byte>()
        for (char in hrp) {
            result.add((char.code shr 5).toByte())
        }
        result.add(0)
        for (char in hrp) {
            result.add((char.code and 0x1F).toByte())
        }
        return result.toByteArray()
    }

    private fun polyMod(values: ByteArray): Int {
        var chk = 1
        for (value in values) {
            val top = chk shr 25
            chk = (chk and 0x1ffffff) shl 5 xor (value.toInt() and 0xFF)
            for (i in 0..4) {
                if ((top shr i) and 1 == 1) {
                    chk = chk xor BECH32_GENERATOR[i]
                }
            }
        }
        return chk
    }
}
