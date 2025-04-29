package com.wannaverse.crypto.core

import kotlin.math.ceil

/**
 * A utility class for reading and writing bytes, shorts, ints, longs, and strings
 * to/from a byte array buffer with position tracking and bit-level operations.
 */
class ByteBuffer private constructor(
    private var buffer: ByteArray,
    private var position: Int = 0,
    private var bitPosition: Int = 0
) {
    companion object {
        private val BIT_MASKS = IntArray(32) { (1 shl it) - 1 }

        /** Creates a new ByteBuffer with the specified size */
        fun create(size: Int): ByteBuffer {
            require(size >= 0) { "Size must be non-negative" }
            return ByteBuffer(ByteArray(size))
        }

        /** Creates a new ByteBuffer from an existing byte array */
        fun from(bytes: ByteArray): ByteBuffer {
            return ByteBuffer(bytes.copyOf())
        }
    }

    // Read operations

    /** Reads a single byte and advances position */
    fun readByte(): Byte = buffer[position++]

    /** Reads a big-endian short and advances position */
    fun readShort(): Short {
        position += 2
        return (((buffer[position - 2].toInt() and 0xFF) shl 8) +
                (buffer[position - 1].toInt() and 0xFF)).toShort()
    }

    /** Reads a big-endian unsigned short and advances position */
    fun readUnsignedShort(): Int {
        position += 2
        return ((buffer[position - 2].toInt() and 0xFF) shl 8) +
                (buffer[position - 1].toInt() and 0xFF)
    }

    /** Reads a big-endian int and advances position */
    fun readInt(): Int {
        position += 4
        return ((buffer[position - 4].toInt() and 0xFF) shl 24) +
                ((buffer[position - 3].toInt() and 0xFF) shl 16) +
                ((buffer[position - 2].toInt() and 0xFF) shl 8) +
                (buffer[position - 1].toInt() and 0xFF)
    }

    /** Reads a big-endian long and advances position */
    fun readLong(): Long {
        val high = (readInt().toLong() and 0xFFFFFFFFL)
        val low = (readInt().toLong() and 0xFFFFFFFFL)
        return (high shl 32) + low
    }

    /** Reads a null-terminated string and advances position */
    fun readString(): String {
        val start = position
        while (position < buffer.size && buffer[position] != 10.toByte()) {
            position++
        }
        if (position >= buffer.size) {
            throw IllegalStateException("String terminator (byte 10) not found")
        }
        val result = buffer.decodeToString(start, position)
        position++
        return result
    }

    /** Reads bytes into destination array and advances position */
    fun readBytes(destination: ByteArray, offset: Int, length: Int) {
        buffer.copyInto(destination, offset, position, position + length)
        position += length
    }

    // Write operations

    /** Writes a single byte and advances position */
    fun writeByte(value: Byte) {
        ensureCapacity(1)
        buffer[position++] = value
    }

    /** Writes a big-endian short and advances position */
    fun writeShort(value: Short) {
        ensureCapacity(2)
        buffer[position++] = (value.toInt() shr 8).toByte()
        buffer[position++] = value.toByte()
    }

    /** Writes a big-endian int and advances position */
    fun writeInt(value: Int) {
        ensureCapacity(4)
        buffer[position++] = (value shr 24).toByte()
        buffer[position++] = (value shr 16).toByte()
        buffer[position++] = (value shr 8).toByte()
        buffer[position++] = value.toByte()
    }

    /** Writes a big-endian long and advances position */
    fun writeLong(value: Long) {
        ensureCapacity(8)
        buffer[position++] = (value shr 56).toByte()
        buffer[position++] = (value shr 48).toByte()
        buffer[position++] = (value shr 40).toByte()
        buffer[position++] = (value shr 32).toByte()
        buffer[position++] = (value shr 24).toByte()
        buffer[position++] = (value shr 16).toByte()
        buffer[position++] = (value shr 8).toByte()
        buffer[position++] = value.toByte()
    }

    /** Writes a string with newline terminator and advances position */
    fun writeString(value: String) {
        val bytes = value.encodeToByteArray()
        ensureCapacity(bytes.size + 1)
        bytes.copyInto(buffer, position)
        position += bytes.size
        buffer[position++] = 10
    }

    /** Writes bytes from source array and advances position */
    fun writeBytes(source: ByteArray, offset: Int, length: Int) {
        ensureCapacity(length)
        source.copyInto(buffer, position, offset, offset + length)
        position += length
    }

    /** Writes bits to the buffer and advances bit position */
    fun writeBits(numBits: Int, value: Int) {
        ensureCapacity(ceil(numBits / 8.0).toInt())
        var remainingBits = numBits
        var bytePos = bitPosition shr 3
        var bitOffset = 8 - (bitPosition and 7)
        bitPosition += numBits

        while (remainingBits > bitOffset) {
            buffer[bytePos] = (buffer[bytePos].toInt() and BIT_MASKS[bitOffset].inv() or
                    ((value shr (remainingBits - bitOffset)) and BIT_MASKS[bitOffset])).toByte()
            bytePos++
            remainingBits -= bitOffset
            bitOffset = 8
        }

        if (remainingBits > 0) {
            buffer[bytePos] = (buffer[bytePos].toInt() and (BIT_MASKS[remainingBits] shl
                    (bitOffset - remainingBits)).inv() or
                    ((value and BIT_MASKS[remainingBits]) shl (bitOffset - remainingBits))).toByte()
        }
    }

    // Utility methods

    /** Resets the buffer to empty */
    fun reset() {
        buffer = ByteArray(0)
        position = 0
        bitPosition = 0
    }

    /** Gets the current position in the buffer */
    fun position(): Int = position

    /** Sets the current position in the buffer */
    fun position(newPosition: Int) {
        require(newPosition in 0..buffer.size) { "Invalid position: $newPosition" }
        position = newPosition
    }

    /** Gets the underlying byte array */
    fun toByteArray(): ByteArray = buffer.copyOf(position)

    private fun ensureCapacity(length: Int) {
        if (position + length > buffer.size) {
            buffer = buffer.copyOf((position + length).coerceAtLeast(buffer.size * 2))
        }
    }
}