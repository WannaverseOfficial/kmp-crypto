package com.wannaverse.crypto.hashing

/**
 * Expect class that provides Argon2 password hashing functionality.
 *
 * Argon2 is a memory-hard key derivation function designed for password hashing.
 * It was the winner of the Password Hashing Competition (PHC) and is defined in RFC 9106.
 *
 * This class supports all three Argon2 variants ([Argon2Type.Argon2d], [Argon2Type.Argon2i],
 * and [Argon2Type.Argon2id]) and allows configuring memory usage, parallelism, iterations,
 * and output hash length via [Argon2Config].
 */
expect class Argon2() {

    /**
     * Hashes a password using the Argon2 algorithm.
     *
     * @param password The password to hash as a byte array.
     * @param salt The salt to use for hashing. Must be at least 8 bytes.
     * @param config The configuration parameters for Argon2 (default is [Argon2Config()]).
     * @return The derived hash as a byte array of length [Argon2Config.hashLength].
     */
    fun hash(password: ByteArray, salt: ByteArray, config: Argon2Config = Argon2Config()): ByteArray
}
