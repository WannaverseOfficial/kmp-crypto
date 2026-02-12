package com.wannaverse.crypto.hashing

/**
 * Native (iOS) implementation of Argon2 password hashing per RFC 9106.
 * Uses a pure Kotlin implementation with Blake2b as the underlying hash function.
 */
actual class Argon2 actual constructor() {

    companion object {
        private const val ARGON2_BLOCK_SIZE = 1024
        private const val ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8
        private const val ARGON2_SYNC_POINTS = 4
        private const val ARGON2_VERSION = 0x13
    }

    actual fun hash(password: ByteArray, salt: ByteArray, config: Argon2Config): ByteArray {
        require(salt.size >= 8) { "Salt must be at least 8 bytes" }
        require(config.hashLength >= 4) { "Hash length must be at least 4 bytes" }
        require(config.parallelism >= 1) { "Parallelism must be at least 1" }
        require(config.memorySizeKB >= 8 * config.parallelism) { "Memory size must be at least 8 * parallelism KB" }
        require(config.iterations >= 1) { "Iterations must be at least 1" }

        val lanes = config.parallelism
        val segmentLength = computeSegmentLength(config.memorySizeKB, lanes)
        val laneLength = segmentLength * ARGON2_SYNC_POINTS
        val memoryBlocks = laneLength * lanes

        val memory = Array(memoryBlocks) { ULongArray(ARGON2_QWORDS_IN_BLOCK) }

        val h0 = computeH0(password, salt, config)

        initializeMemory(memory, h0, lanes, laneLength)

        fillMemory(memory, config, lanes, segmentLength, laneLength)

        return finalize(memory, config, lanes, laneLength)
    }

    private fun computeSegmentLength(memorySizeKB: Int, lanes: Int): Int {
        val totalBlocks = maxOf(memorySizeKB, 8 * lanes)
        val segmentLength = totalBlocks / (lanes * ARGON2_SYNC_POINTS)
        return maxOf(segmentLength, 1)
    }

    private fun computeH0(password: ByteArray, salt: ByteArray, config: Argon2Config): ByteArray {
        val typeValue = when (config.type) {
            Argon2Type.Argon2d -> 0
            Argon2Type.Argon2i -> 1
            Argon2Type.Argon2id -> 2
        }

        val b2b = Blake2b(64)
        b2b.update(intToLittleEndian(config.parallelism))
        b2b.update(intToLittleEndian(config.hashLength))
        b2b.update(intToLittleEndian(config.memorySizeKB))
        b2b.update(intToLittleEndian(config.iterations))
        b2b.update(intToLittleEndian(ARGON2_VERSION))
        b2b.update(intToLittleEndian(typeValue))
        b2b.update(intToLittleEndian(password.size))
        b2b.update(password)
        b2b.update(intToLittleEndian(salt.size))
        b2b.update(salt)
        b2b.update(intToLittleEndian(0)) // key length = 0
        b2b.update(intToLittleEndian(0)) // associated data length = 0
        return b2b.digest()
    }

    private fun initializeMemory(
        memory: Array<ULongArray>,
        h0: ByteArray,
        lanes: Int,
        laneLength: Int,
    ) {
        for (lane in 0 until lanes) {
            val input0 = h0 + intToLittleEndian(0) + intToLittleEndian(lane)
            val hash0 = blake2bLong(input0, ARGON2_BLOCK_SIZE)
            loadBlock(memory[lane * laneLength], hash0)

            val input1 = h0 + intToLittleEndian(1) + intToLittleEndian(lane)
            val hash1 = blake2bLong(input1, ARGON2_BLOCK_SIZE)
            loadBlock(memory[lane * laneLength + 1], hash1)
        }
    }

    private fun fillMemory(
        memory: Array<ULongArray>,
        config: Argon2Config,
        lanes: Int,
        segmentLength: Int,
        laneLength: Int,
    ) {
        for (pass in 0 until config.iterations) {
            for (slice in 0 until ARGON2_SYNC_POINTS) {
                for (lane in 0 until lanes) {
                    fillSegment(memory, config, pass, lane, slice, lanes, segmentLength, laneLength)
                }
            }
        }
    }

    private fun fillSegment(
        memory: Array<ULongArray>,
        config: Argon2Config,
        pass: Int,
        lane: Int,
        slice: Int,
        lanes: Int,
        segmentLength: Int,
        laneLength: Int,
    ) {
        val dataIndependent = config.type == Argon2Type.Argon2i ||
                (config.type == Argon2Type.Argon2id && pass == 0 && slice < 2)

        var pseudoRands: ULongArray? = null
        if (dataIndependent) {
            pseudoRands = generatePseudoRands(pass, lane, slice, lanes, config.iterations, config.type, segmentLength, laneLength)
        }

        val startIndex = if (pass == 0 && slice == 0) 2 else 0

        for (index in startIndex until segmentLength) {
            val curIndex = lane * laneLength + slice * segmentLength + index
            val prevIndex = if (curIndex == lane * laneLength) {
                lane * laneLength + laneLength - 1
            } else {
                curIndex - 1
            }

            val pseudoRand = if (dataIndependent) {
                pseudoRands!![index]
            } else {
                memory[prevIndex][0]
            }

            val refLane: Int
            val refIndex: Int

            if (pass == 0 && slice == 0) {
                refLane = lane
                refIndex = computeRefIndex(pseudoRand, index, segmentLength, lane, lane, pass, slice, lanes, laneLength)
            } else {
                val rl = ((pseudoRand shr 32) % lanes.toULong()).toInt()
                refLane = if (pass == 0) lane else rl
                refIndex = computeRefIndex(pseudoRand, index, segmentLength, lane, refLane, pass, slice, lanes, laneLength)
            }

            val refBlockIndex = refLane * laneLength + refIndex

            if (pass == 0) {
                compressBlock(memory[curIndex], memory[prevIndex], memory[refBlockIndex])
            } else {
                compressBlockXor(memory[curIndex], memory[prevIndex], memory[refBlockIndex])
            }
        }
    }

    private fun computeRefIndex(
        pseudoRand: ULong,
        index: Int,
        segmentLength: Int,
        curLane: Int,
        refLane: Int,
        pass: Int,
        slice: Int,
        lanes: Int,
        laneLength: Int,
    ): Int {
        val referenceAreaSize: Int
        val startPosition: Int

        if (pass == 0) {
            if (slice == 0) {
                referenceAreaSize = index - 1
                startPosition = 0
            } else {
                if (curLane == refLane) {
                    referenceAreaSize = slice * segmentLength + index - 1
                    startPosition = 0
                } else {
                    referenceAreaSize = slice * segmentLength + if (index == 0) -1 else 0
                    startPosition = 0
                }
            }
        } else {
            if (curLane == refLane) {
                referenceAreaSize = laneLength - segmentLength + index - 1
                startPosition = (slice + 1) * segmentLength
            } else {
                referenceAreaSize = laneLength - segmentLength + if (index == 0) -1 else 0
                startPosition = (slice + 1) * segmentLength
            }
        }

        if (referenceAreaSize <= 0) return 0

        val j1 = (pseudoRand and 0xFFFFFFFFuL)
        val x = (j1 * j1) shr 32
        val y = (referenceAreaSize.toULong() * x) shr 32
        val relativePosition = (referenceAreaSize.toULong() - 1uL - y).toInt()

        return (startPosition + relativePosition) % laneLength
    }

    private fun generatePseudoRands(
        pass: Int,
        lane: Int,
        slice: Int,
        lanes: Int,
        iterations: Int,
        type: Argon2Type,
        segmentLength: Int,
        laneLength: Int,
    ): ULongArray {
        val result = ULongArray(segmentLength)
        val inputBlock = ULongArray(ARGON2_QWORDS_IN_BLOCK)
        val addressBlock = ULongArray(ARGON2_QWORDS_IN_BLOCK)
        val tmpBlock = ULongArray(ARGON2_QWORDS_IN_BLOCK)

        inputBlock[0] = pass.toULong()
        inputBlock[1] = lane.toULong()
        inputBlock[2] = slice.toULong()
        inputBlock[3] = (lanes * laneLength).toULong()
        inputBlock[4] = iterations.toULong()
        inputBlock[5] = when (type) {
            Argon2Type.Argon2d -> 0uL
            Argon2Type.Argon2i -> 1uL
            Argon2Type.Argon2id -> 2uL
        }

        for (i in 0 until segmentLength step ARGON2_QWORDS_IN_BLOCK) {
            inputBlock[6] = (inputBlock[6] + 1uL)
            compressBlock(tmpBlock, inputBlock, ULongArray(ARGON2_QWORDS_IN_BLOCK))
            compressBlock(addressBlock, tmpBlock, ULongArray(ARGON2_QWORDS_IN_BLOCK))

            val count = minOf(ARGON2_QWORDS_IN_BLOCK, segmentLength - i)
            for (j in 0 until count) {
                result[i + j] = addressBlock[j]
            }
        }

        return result
    }

    private fun compressBlock(
        result: ULongArray,
        x: ULongArray,
        y: ULongArray,
    ) {
        val r = ULongArray(ARGON2_QWORDS_IN_BLOCK)
        for (i in 0 until ARGON2_QWORDS_IN_BLOCK) {
            r[i] = x[i] xor y[i]
        }

        val z = r.copyOf()
        applyBlake2bRounds(z)

        for (i in 0 until ARGON2_QWORDS_IN_BLOCK) {
            result[i] = r[i] xor z[i]
        }
    }

    private fun compressBlockXor(
        result: ULongArray,
        x: ULongArray,
        y: ULongArray,
    ) {
        val r = ULongArray(ARGON2_QWORDS_IN_BLOCK)
        for (i in 0 until ARGON2_QWORDS_IN_BLOCK) {
            r[i] = x[i] xor y[i]
        }

        val z = r.copyOf()
        applyBlake2bRounds(z)

        for (i in 0 until ARGON2_QWORDS_IN_BLOCK) {
            result[i] = result[i] xor r[i] xor z[i]
        }
    }

    private fun applyBlake2bRounds(block: ULongArray) {
        // Apply Blake2b round function to rows
        for (i in 0 until 8) {
            val base = i * 16
            blamkaG(block, base, base + 1, base + 2, base + 3, base + 4, base + 5, base + 6, base + 7,
                base + 8, base + 9, base + 10, base + 11, base + 12, base + 13, base + 14, base + 15)
        }

        // Apply Blake2b round function to columns
        for (i in 0 until 8) {
            val i0 = i * 2
            val i1 = i * 2 + 1
            blamkaG(block, i0, i1, i0 + 16, i1 + 16, i0 + 32, i1 + 32, i0 + 48, i1 + 48,
                i0 + 64, i1 + 64, i0 + 80, i1 + 80, i0 + 96, i1 + 96, i0 + 112, i1 + 112)
        }
    }

    private fun blamkaG(
        block: ULongArray,
        i0: Int, i1: Int, i2: Int, i3: Int,
        i4: Int, i5: Int, i6: Int, i7: Int,
        i8: Int, i9: Int, i10: Int, i11: Int,
        i12: Int, i13: Int, i14: Int, i15: Int,
    ) {
        gB(block, i0, i4, i8, i12)
        gB(block, i1, i5, i9, i13)
        gB(block, i2, i6, i10, i14)
        gB(block, i3, i7, i11, i15)
        gB(block, i0, i5, i10, i15)
        gB(block, i1, i6, i11, i12)
        gB(block, i2, i7, i8, i13)
        gB(block, i3, i4, i9, i14)
    }

    private fun gB(block: ULongArray, a: Int, b: Int, c: Int, d: Int) {
        block[a] = fBlaMka(block[a], block[b])
        block[d] = (block[d] xor block[a]).rotateRight64(32)
        block[c] = fBlaMka(block[c], block[d])
        block[b] = (block[b] xor block[c]).rotateRight64(24)
        block[a] = fBlaMka(block[a], block[b])
        block[d] = (block[d] xor block[a]).rotateRight64(16)
        block[c] = fBlaMka(block[c], block[d])
        block[b] = (block[b] xor block[c]).rotateRight64(63)
    }

    private fun fBlaMka(x: ULong, y: ULong): ULong {
        val lower = (x and 0xFFFFFFFFuL) * (y and 0xFFFFFFFFuL)
        return x + y + (lower shl 1)
    }

    private fun ULong.rotateRight64(n: Int): ULong =
        (this shr n) or (this shl (64 - n))

    private fun finalize(
        memory: Array<ULongArray>,
        config: Argon2Config,
        lanes: Int,
        laneLength: Int,
    ): ByteArray {
        val finalBlock = ULongArray(ARGON2_QWORDS_IN_BLOCK)
        memory[(lanes - 1) * laneLength + laneLength - 1].copyInto(finalBlock)

        for (lane in 0 until lanes - 1) {
            val lastBlockIndex = lane * laneLength + laneLength - 1
            for (i in 0 until ARGON2_QWORDS_IN_BLOCK) {
                finalBlock[i] = finalBlock[i] xor memory[lastBlockIndex][i]
            }
        }

        val finalBytes = blockToBytes(finalBlock)
        return blake2bLong(finalBytes, config.hashLength)
    }

    private fun blake2bLong(input: ByteArray, outputLength: Int): ByteArray {
        if (outputLength <= 64) {
            val b2b = Blake2b(outputLength)
            b2b.update(intToLittleEndian(outputLength))
            b2b.update(input)
            return b2b.digest()
        }

        // For longer outputs, produce 64-byte blocks using Blake2b
        val result = ByteArray(outputLength)

        // First block: V1 = H^(64)(outputLength || input)
        var v = Blake2b(64).let { b ->
            b.update(intToLittleEndian(outputLength))
            b.update(input)
            b.digest()
        }
        v.copyInto(result, 0, 0, 32)

        var pos = 32
        val remaining = outputLength - 32
        val fullBlocks = remaining / 32

        for (i in 1 until fullBlocks) {
            v = Blake2b.hash(v, 64)
            v.copyInto(result, pos, 0, 32)
            pos += 32
        }

        // Last block
        val lastSize = outputLength - pos
        v = Blake2b.hash(v, lastSize)
        v.copyInto(result, pos, 0, lastSize)

        return result
    }

    private fun loadBlock(block: ULongArray, bytes: ByteArray) {
        for (i in 0 until ARGON2_QWORDS_IN_BLOCK) {
            block[i] = loadLittleEndian64(bytes, i * 8)
        }
    }

    private fun blockToBytes(block: ULongArray): ByteArray {
        val bytes = ByteArray(ARGON2_BLOCK_SIZE)
        for (i in 0 until ARGON2_QWORDS_IN_BLOCK) {
            storeLittleEndian64(bytes, i * 8, block[i])
        }
        return bytes
    }

    private fun intToLittleEndian(value: Int): ByteArray {
        return byteArrayOf(
            (value and 0xFF).toByte(),
            ((value shr 8) and 0xFF).toByte(),
            ((value shr 16) and 0xFF).toByte(),
            ((value shr 24) and 0xFF).toByte(),
        )
    }

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

    private fun storeLittleEndian64(bytes: ByteArray, offset: Int, value: ULong) {
        bytes[offset] = (value and 0xFFuL).toByte()
        bytes[offset + 1] = ((value shr 8) and 0xFFuL).toByte()
        bytes[offset + 2] = ((value shr 16) and 0xFFuL).toByte()
        bytes[offset + 3] = ((value shr 24) and 0xFFuL).toByte()
        bytes[offset + 4] = ((value shr 32) and 0xFFuL).toByte()
        bytes[offset + 5] = ((value shr 40) and 0xFFuL).toByte()
        bytes[offset + 6] = ((value shr 48) and 0xFFuL).toByte()
        bytes[offset + 7] = ((value shr 56) and 0xFFuL).toByte()
    }
}
