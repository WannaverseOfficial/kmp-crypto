package com.wannaverse.crypto.core

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault
import kotlin.math.*

actual class SecureRandom {
    private var hasCachedGaussian = false
    private var cachedGaussian = 0.0

    @OptIn(ExperimentalForeignApi::class)
    actual fun nextBytes(length: Int): ByteArray {
        val result = ByteArray(length)
        result.usePinned {
            val status = SecRandomCopyBytes(kSecRandomDefault, length.toULong(), it.addressOf(0))
            if (status != 0) {
                throw RuntimeException("Failed to generate secure random bytes: $status")
            }
        }
        return result
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun nextBytes(array: ByteArray) {
        array.usePinned {
            val status = SecRandomCopyBytes(kSecRandomDefault, array.size.toULong(), it.addressOf(0))
            if (status != 0) {
                throw RuntimeException("Failed to generate secure random bytes: $status")
            }
        }
    }

    actual fun nextInt(): Int {
        val bytes = nextBytes(4)
        return bytes.foldIndexed(0) { i, acc, byte ->
            acc or ((byte.toInt() and 0xFF) shl (8 * (3 - i)))
        }
    }

    actual fun nextInt(bound: Int): Int {
        require(bound > 0) { "Bound must be positive" }
        val max = UInt.MAX_VALUE.toInt()
        val threshold = max - (max % bound)

        var r: Int
        do {
            r = nextInt() ushr 1 // avoid signed int overflow
        } while (r >= threshold)
        return r % bound
    }

    actual fun nextLong(): Long {
        val bytes = nextBytes(8)
        return bytes.foldIndexed(0L) { i, acc, byte ->
            acc or ((byte.toLong() and 0xFF) shl (8 * (7 - i)))
        }
    }

    actual fun nextBoolean(): Boolean {
        return (nextBytes(1)[0].toInt() and 0x01) == 0
    }

    actual fun nextDouble(): Double {
        // Convert a 53-bit integer to a double between 0 and 1
        val long = nextLong().ushr(11) and ((1L shl 53) - 1)
        return long.toDouble() / (1L shl 53).toDouble()
    }

    actual fun nextFloat(): Float {
        return nextInt().ushr(9).toFloat() / (1 shl 23).toFloat()
    }

    actual fun nextGaussian(): Double {
        if (hasCachedGaussian) {
            hasCachedGaussian = false
            return cachedGaussian
        }

        var u: Double
        var v: Double
        do {
            u = nextDouble()
            v = nextDouble()
        } while (u <= 0.0)

        val radius = sqrt(-2.0 * ln(u))
        val theta = 2.0 * PI * v

        cachedGaussian = radius * sin(theta)
        hasCachedGaussian = true
        return radius * cos(theta)
    }
}
