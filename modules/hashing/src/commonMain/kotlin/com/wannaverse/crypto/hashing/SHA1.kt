package com.wannaverse.crypto.hashing

/**
 * Computes the SHA-1 hash of the given byte array.
 *
 * @param input The input data as a byte array to be hashed.
 * @return The SHA-1 hash of the input as a byte array.
 *
 */
expect fun sha1(input: ByteArray): ByteArray