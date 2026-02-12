package com.wannaverse.crypto.hashing

import java.security.MessageDigest

private val sha384Digest = MessageDigest.getInstance("SHA-384")

actual fun sha384(input: ByteArray): ByteArray {
    return sha384Digest.digest(input)
}
