package com.wannaverse.crypto.jwt

/**
 * Converts a DER-encoded ECDSA signature to the raw R||S format required by JWT (RFC 7518 Section 3.4).
 *
 * @param der The DER-encoded signature.
 * @param componentLength The byte length of each R and S component (32 for P-256, 48 for P-384, 66 for P-521).
 * @return The raw R||S signature.
 */
internal fun derToRawSignature(der: ByteArray, componentLength: Int): ByteArray {
    // DER format: 0x30 <totalLen> 0x02 <rLen> <r> 0x02 <sLen> <s>
    var offset = 0
    require(der[offset++].toInt() == 0x30) { "Invalid DER signature: expected SEQUENCE" }

    // Skip total length (may be 1 or 2 bytes)
    val totalLen = readDerLength(der, offset)
    offset += totalLen.second

    // Read R
    require(der[offset++].toInt() == 0x02) { "Invalid DER signature: expected INTEGER for R" }
    val rLen = der[offset++].toInt() and 0xFF
    val rBytes = der.copyOfRange(offset, offset + rLen)
    offset += rLen

    // Read S
    require(der[offset++].toInt() == 0x02) { "Invalid DER signature: expected INTEGER for S" }
    val sLen = der[offset++].toInt() and 0xFF
    val sBytes = der.copyOfRange(offset, offset + sLen)

    // Pad or trim R and S to fixed componentLength
    val r = toFixedLength(rBytes, componentLength)
    val s = toFixedLength(sBytes, componentLength)

    return r + s
}

/**
 * Converts a raw R||S JWT signature back to DER encoding for platform verification APIs.
 *
 * @param raw The raw R||S signature.
 * @param componentLength The byte length of each R and S component.
 * @return The DER-encoded signature.
 */
internal fun rawToDerSignature(raw: ByteArray, componentLength: Int): ByteArray {
    require(raw.size == componentLength * 2) { "Invalid raw signature length: expected ${componentLength * 2}, got ${raw.size}" }

    val r = raw.copyOfRange(0, componentLength)
    val s = raw.copyOfRange(componentLength, componentLength * 2)

    val rDer = toDerInteger(r)
    val sDer = toDerInteger(s)

    val contentLength = rDer.size + sDer.size
    val result = mutableListOf<Byte>()
    result.add(0x30.toByte()) // SEQUENCE
    if (contentLength < 128) {
        result.add(contentLength.toByte())
    } else {
        result.add(0x81.toByte())
        result.add(contentLength.toByte())
    }
    result.addAll(rDer.toList())
    result.addAll(sDer.toList())
    return result.toByteArray()
}

/**
 * Reads a DER length field.
 * @return Pair of (length value, number of bytes consumed)
 */
private fun readDerLength(data: ByteArray, offset: Int): Pair<Int, Int> {
    val first = data[offset].toInt() and 0xFF
    return if (first < 128) {
        Pair(first, 1)
    } else {
        val numBytes = first and 0x7F
        var length = 0
        for (i in 1..numBytes) {
            length = (length shl 8) or (data[offset + i].toInt() and 0xFF)
        }
        Pair(length, 1 + numBytes)
    }
}

/**
 * Converts a raw integer byte array to a fixed-length representation,
 * trimming leading zero padding or left-padding with zeros.
 */
private fun toFixedLength(bytes: ByteArray, length: Int): ByteArray {
    return when {
        bytes.size == length -> bytes
        bytes.size > length -> {
            // Trim leading zeros (DER integers may have a leading 0x00 for sign)
            val start = bytes.size - length
            bytes.copyOfRange(start, bytes.size)
        }
        else -> {
            // Left-pad with zeros
            ByteArray(length - bytes.size) + bytes
        }
    }
}

/**
 * Encodes a raw integer as a DER INTEGER.
 * Strips leading zeros but ensures the high bit indicates positive.
 */
private fun toDerInteger(value: ByteArray): ByteArray {
    // Strip leading zeros
    var start = 0
    while (start < value.size - 1 && value[start] == 0.toByte()) {
        start++
    }
    val trimmed = value.copyOfRange(start, value.size)

    // If high bit is set, prepend 0x00 to indicate positive integer
    val needsPadding = (trimmed[0].toInt() and 0x80) != 0
    val intBytes = if (needsPadding) byteArrayOf(0) + trimmed else trimmed

    return byteArrayOf(0x02.toByte(), intBytes.size.toByte()) + intBytes
}
