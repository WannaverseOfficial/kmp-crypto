package com.wannaverse.crypto.hashing

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CCHmac
import platform.CoreCrypto.kCCHmacAlgSHA256
import platform.CoreCrypto.kCCHmacAlgSHA384
import platform.CoreCrypto.kCCHmacAlgSHA512

@OptIn(ExperimentalForeignApi::class)
actual object HMAC {
    actual fun sign(key: ByteArray, data: ByteArray, algorithm: HmacAlgorithm): ByteArray {
        val ccAlgorithm = when (algorithm) {
            HmacAlgorithm.HMAC_SHA256 -> kCCHmacAlgSHA256
            HmacAlgorithm.HMAC_SHA384 -> kCCHmacAlgSHA384
            HmacAlgorithm.HMAC_SHA512 -> kCCHmacAlgSHA512
        }
        val digest = UByteArray(algorithm.digestLength)
        key.usePinned { keyPinned ->
            data.usePinned { dataPinned ->
                digest.usePinned { digestPinned ->
                    CCHmac(
                        ccAlgorithm,
                        keyPinned.addressOf(0),
                        key.size.convert(),
                        dataPinned.addressOf(0),
                        data.size.convert(),
                        digestPinned.addressOf(0)
                    )
                }
            }
        }
        return digest.asByteArray()
    }

    actual fun verify(key: ByteArray, data: ByteArray, signature: ByteArray, algorithm: HmacAlgorithm): Boolean {
        val computed = sign(key, data, algorithm)
        if (computed.size != signature.size) return false
        var result = 0
        for (i in computed.indices) {
            result = result or (computed[i].toInt() xor signature[i].toInt())
        }
        return result == 0
    }
}
