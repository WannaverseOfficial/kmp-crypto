package com.wannaverse.crypto.hashing

import java.security.MessageDigest

private val sha512Digest = MessageDigest.getInstance("SHA-512")

actual fun sha512(input: ByteArray): ByteArray {
    return sha512Digest.digest(input)
}