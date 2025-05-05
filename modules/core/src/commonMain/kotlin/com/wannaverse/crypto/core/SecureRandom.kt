package com.wannaverse.crypto.core

expect class SecureRandom() {
    fun nextBytes(length: Int): ByteArray
    fun nextBytes(array: ByteArray)

    fun nextInt(): Int
    fun nextInt(bound: Int): Int
    fun nextLong(): Long
    fun nextBoolean(): Boolean
    fun nextDouble(): Double
    fun nextFloat(): Float
    fun nextGaussian(): Double
}
