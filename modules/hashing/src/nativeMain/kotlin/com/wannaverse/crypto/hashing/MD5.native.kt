package com.wannaverse.crypto.hashing

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_MD5
import platform.CoreCrypto.CC_MD5_DIGEST_LENGTH

@OptIn(ExperimentalForeignApi::class)
actual fun md5(input: ByteArray): ByteArray {
    val digest = UByteArray(CC_MD5_DIGEST_LENGTH)
    input.usePinned { pinned ->
        digest.usePinned {
            CC_MD5(pinned.addressOf(0), input.size.convert(), it.addressOf(0))
        }
    }
    return digest.asByteArray()
}