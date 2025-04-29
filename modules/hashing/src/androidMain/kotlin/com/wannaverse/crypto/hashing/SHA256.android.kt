package com.wannaverse.crypto.hashing

import java.security.MessageDigest

private val sha256Digest = MessageDigest.getInstance("SHA-256")

actual fun sha256(input: ByteArray): ByteArray {
    return sha256Digest.digest(input)
}