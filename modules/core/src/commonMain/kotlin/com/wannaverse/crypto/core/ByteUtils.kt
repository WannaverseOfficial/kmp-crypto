package com.wannaverse.crypto.core

/**
 * Utility object for secure and low-level byte array operations.
 */
object ByteUtils {

    /**
     * Compares two byte arrays for equality in constant time to prevent timing attacks.
     *
     * This function ensures that the comparison takes the same amount of time regardless
     * of how early the arrays differ, which helps defend against side-channel attacks.
     *
     * @param a The first byte array.
     * @param b The second byte array.
     * @return `true` if the arrays are equal in content and length, `false` otherwise.
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }

    /**
     * Securely wipes (zeros out) the contents of the given byte array.
     *
     * This is useful for clearing sensitive data (e.g., cryptographic keys or passwords)
     * from memory after use.
     *
     * @param array The byte array to wipe.
     */
    fun wipe(array: ByteArray) {
        for (i in array.indices) {
            array[i] = 0
        }
    }
}