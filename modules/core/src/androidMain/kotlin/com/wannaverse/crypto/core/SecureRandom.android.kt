package com.wannaverse.crypto.core

import java.security.SecureRandom as JavaSecureRandom

actual class SecureRandom {
    private val jSecureRandom = JavaSecureRandom()

    actual fun nextBytes(length: Int): ByteArray
            = ByteArray(length).also { jSecureRandom.nextBytes(it) }

    actual fun nextBytes(array: ByteArray) {
        jSecureRandom.nextBytes(array)
    }

    actual fun nextInt(): Int = jSecureRandom.nextInt()

    actual fun nextInt(bound: Int): Int = jSecureRandom.nextInt(bound)

    actual fun nextLong(): Long = jSecureRandom.nextLong()

    actual fun nextBoolean(): Boolean = jSecureRandom.nextBoolean()

    actual fun nextDouble(): Double = jSecureRandom.nextDouble()

    actual fun nextFloat(): Float = jSecureRandom.nextFloat()

    actual fun nextGaussian(): Double = jSecureRandom.nextGaussian()
}