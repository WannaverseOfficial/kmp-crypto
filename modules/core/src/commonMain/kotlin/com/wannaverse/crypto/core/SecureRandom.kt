package com.wannaverse.crypto.core

/**
 * A cryptographically secure random number generator.
 *
 * This class provides methods to generate random values of different types using secure random algorithms,
 * suitable for cryptographic operations where unpredictability and randomness are crucial.
 */
expect class SecureRandom {

    /**
     * Generates a random byte array of the specified length.
     *
     * @param length The length of the byte array to generate.
     * @return A byte array of the specified length filled with random values.
     */
    fun nextBytes(length: Int): ByteArray

    /**
     * Fills the provided byte array with random values.
     *
     * @param array The byte array to be filled with random values.
     */
    fun nextBytes(array: ByteArray)

    /**
     * Generates a random integer.
     *
     * @return A random integer.
     */
    fun nextInt(): Int

    /**
     * Generates a random integer within the specified bound.
     *
     * @param bound The upper bound (exclusive) for the generated random integer.
     * @return A random integer in the range [0, bound).
     * @throws IllegalArgumentException If bound is non-positive.
     */
    fun nextInt(bound: Int): Int

    /**
     * Generates a random long value.
     *
     * @return A random long value.
     */
    fun nextLong(): Long

    /**
     * Generates a random boolean value.
     *
     * @return A random boolean value, either `true` or `false`.
     */
    fun nextBoolean(): Boolean

    /**
     * Generates a random double value between 0.0 (inclusive) and 1.0 (exclusive).
     *
     * @return A random double value in the range [0.0, 1.0).
     */
    fun nextDouble(): Double

    /**
     * Generates a random float value between 0.0 (inclusive) and 1.0 (exclusive).
     *
     * @return A random float value in the range [0.0, 1.0).
     */
    fun nextFloat(): Float

    /**
     * Generates a random Gaussian (normal) distribution value.
     *
     * The value is drawn from a Gaussian (normal) distribution with a mean of 0.0 and a standard deviation of 1.0.
     *
     * @return A random value following a Gaussian distribution.
     */
    fun nextGaussian(): Double
}
