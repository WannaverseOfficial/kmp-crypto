package com.wannaverse.crypto.hashing

import java.security.MessageDigest

private val md5Digest = MessageDigest.getInstance("MD5")

actual fun md5(input: ByteArray): ByteArray {
    return md5Digest.digest(input)
}