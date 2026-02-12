package com.wannaverse.crypto.hashing

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA384
import platform.CoreCrypto.CC_SHA384_DIGEST_LENGTH

@OptIn(ExperimentalForeignApi::class)
actual fun sha384(input: ByteArray): ByteArray {
    val digest = UByteArray(CC_SHA384_DIGEST_LENGTH)
    input.usePinned { pinned ->
        digest.usePinned {
            CC_SHA384(pinned.addressOf(0), input.size.convert(), it.addressOf(0))
        }
    }
    return digest.asByteArray()
}
