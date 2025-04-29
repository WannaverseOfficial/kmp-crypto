package com.wannaverse.crypto.hashing

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA1
import platform.CoreCrypto.CC_SHA1_DIGEST_LENGTH

@OptIn(ExperimentalForeignApi::class)
actual fun sha1(input: ByteArray): ByteArray {
    val digest = UByteArray(CC_SHA1_DIGEST_LENGTH)
    input.usePinned { pinned ->
        digest.usePinned {
            CC_SHA1(pinned.addressOf(0), input.size.convert(), it.addressOf(0))
        }
    }
    return digest.asByteArray()
}