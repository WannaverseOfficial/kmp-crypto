package com.wannaverse.crypto.hashing

/**
 * Enum representing the different variants of the Argon2 password hashing algorithm.
 *
 * Each variant offers different trade-offs between resistance to side-channel attacks
 * and resistance to GPU/ASIC-based attacks.
 *
 * - [Argon2d]: Data-dependent memory access, providing maximum resistance to GPU cracking
 *   but vulnerable to side-channel attacks. Best for cryptocurrency and backend applications.
 * - [Argon2i]: Data-independent memory access, providing resistance to side-channel attacks.
 *   Suitable for password hashing where side-channel attacks are a concern.
 * - [Argon2id]: Hybrid mode that combines Argon2i for the first half of the first pass
 *   and Argon2d for the rest. Recommended for most password hashing use cases.
 */
enum class Argon2Type {
    Argon2d,
    Argon2i,
    Argon2id
}
