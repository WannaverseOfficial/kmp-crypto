package com.wannaverse.crypto.hashing

import java.security.MessageDigest

private val sha1Digest = MessageDigest.getInstance("SHA-1")

actual fun sha1(input: ByteArray): ByteArray {
    return sha1Digest.digest(input)
}