package com.wannaverse.crypto.hashing

/**
 * Internal Blake2b implementation used by the Argon2 algorithm.
 * Implements the Blake2b hash function as specified in RFC 7693.
 */
internal class Blake2b(digestLength: Int, key: ByteArray = ByteArray(0)) {

    companion object {
        private val IV = ulongArrayOf(
            0x6A09E667F3BCC908uL,
            0xBB67AE8584CAA73BuL,
            0x3C6EF372FE94F82BuL,
            0xA54FF53A5F1D36F1uL,
            0x510E527FADE682D1uL,
            0x9B05688C2B3E6C1FuL,
            0x1F83D9ABFB41BD6BuL,
            0x5BE0CD19137E2179uL,
        )

        private val SIGMA = arrayOf(
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        )

        private const val BLOCK_SIZE = 128

        fun hash(input: ByteArray, digestLength: Int): ByteArray {
            val b2b = Blake2b(digestLength)
            b2b.update(input)
            return b2b.digest()
        }
    }

    private val h = ULongArray(8)
    private val buffer = ByteArray(BLOCK_SIZE)
    private var bufferOffset = 0
    private var t0: ULong = 0uL
    private var t1: ULong = 0uL
    private val digestLength: Int

    init {
        require(digestLength in 1..64) { "Digest length must be between 1 and 64" }
        require(key.size <= 64) { "Key length must be at most 64" }
        this.digestLength = digestLength

        IV.copyInto(h)
        h[0] = h[0] xor (0x01010000uL or (key.size.toULong() shl 8) or digestLength.toULong())

        if (key.isNotEmpty()) {
            val keyBlock = ByteArray(BLOCK_SIZE)
            key.copyInto(keyBlock)
            update(keyBlock)
        }
    }

    fun update(input: ByteArray) {
        var offset = 0
        var remaining = input.size

        if (bufferOffset > 0) {
            val toCopy = minOf(BLOCK_SIZE - bufferOffset, remaining)
            input.copyInto(buffer, bufferOffset, offset, offset + toCopy)
            bufferOffset += toCopy
            offset += toCopy
            remaining -= toCopy

            if (bufferOffset == BLOCK_SIZE && remaining > 0) {
                incrementCounter(BLOCK_SIZE)
                compress(buffer, false)
                bufferOffset = 0
            }
        }

        while (remaining > BLOCK_SIZE) {
            incrementCounter(BLOCK_SIZE)
            compress(input, false, offset)
            offset += BLOCK_SIZE
            remaining -= BLOCK_SIZE
        }

        if (remaining > 0) {
            input.copyInto(buffer, bufferOffset, offset, offset + remaining)
            bufferOffset += remaining
        }
    }

    fun digest(): ByteArray {
        incrementCounter(bufferOffset)
        for (i in bufferOffset until BLOCK_SIZE) {
            buffer[i] = 0
        }
        compress(buffer, true)

        val out = ByteArray(digestLength)
        for (i in 0 until digestLength) {
            out[i] = (h[i / 8] shr (8 * (i % 8))).toByte()
        }
        return out
    }

    private fun incrementCounter(amount: Int) {
        t0 += amount.toULong()
        if (t0 < amount.toULong()) {
            t1++
        }
    }

    private fun compress(block: ByteArray, last: Boolean, offset: Int = 0) {
        val v = ULongArray(16)
        val m = ULongArray(16)

        for (i in 0..7) {
            v[i] = h[i]
        }
        v[8] = IV[0]
        v[9] = IV[1]
        v[10] = IV[2]
        v[11] = IV[3]
        v[12] = IV[4] xor t0
        v[13] = IV[5] xor t1
        v[14] = if (last) IV[6].inv() else IV[6]
        v[15] = IV[7]

        for (i in 0..15) {
            m[i] = loadLittleEndian64(block, offset + i * 8)
        }

        for (i in 0..11) {
            val s = SIGMA[i]
            mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for (i in 0..7) {
            h[i] = h[i] xor v[i] xor v[i + 8]
        }
    }

    private fun mix(v: ULongArray, a: Int, b: Int, c: Int, d: Int, x: ULong, y: ULong) {
        v[a] = v[a] + v[b] + x
        v[d] = (v[d] xor v[a]).rotateRight(32)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(24)
        v[a] = v[a] + v[b] + y
        v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(63)
    }

    private fun ULong.rotateRight(n: Int): ULong =
        (this shr n) or (this shl (64 - n))

    private fun loadLittleEndian64(bytes: ByteArray, offset: Int): ULong {
        return (bytes[offset].toULong() and 0xFFuL) or
                ((bytes[offset + 1].toULong() and 0xFFuL) shl 8) or
                ((bytes[offset + 2].toULong() and 0xFFuL) shl 16) or
                ((bytes[offset + 3].toULong() and 0xFFuL) shl 24) or
                ((bytes[offset + 4].toULong() and 0xFFuL) shl 32) or
                ((bytes[offset + 5].toULong() and 0xFFuL) shl 40) or
                ((bytes[offset + 6].toULong() and 0xFFuL) shl 48) or
                ((bytes[offset + 7].toULong() and 0xFFuL) shl 56)
    }
}
