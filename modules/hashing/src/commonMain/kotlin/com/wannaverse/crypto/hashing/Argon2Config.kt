package com.wannaverse.crypto.hashing

/**
 * Configuration class for Argon2 password hashing parameters.
 *
 * This class holds the parameters that control the behavior and security of Argon2 operations.
 * The default values provide a reasonable balance of security and performance for most use cases.
 *
 * @property type The Argon2 variant to use (default is [Argon2Type.Argon2id]).
 * @property hashLength The desired length of the output hash in bytes (default is 32).
 * @property parallelism The degree of parallelism (number of lanes) (default is 1).
 * @property memorySizeKB The amount of memory to use in kibibytes (default is 65536, i.e. 64 MB).
 * @property iterations The number of passes over the memory (default is 3).
 */
data class Argon2Config(
    val type: Argon2Type = Argon2Type.Argon2id,
    val hashLength: Int = 32,
    val parallelism: Int = 1,
    val memorySizeKB: Int = 65536,
    val iterations: Int = 3,
)
