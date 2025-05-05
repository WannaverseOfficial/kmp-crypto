package com.wannaverse.crypto.hashing

/**
 * Computes the MD5 hash of the given byte array.
 *
 * @param input The input data as a byte array to be hashed.
 * @return The MD5 hash of the input as a byte array.
 *
 */
expect fun md5(input: ByteArray): ByteArray