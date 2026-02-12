package com.wannaverse.crypto.hashing

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

actual object HMAC {
    actual fun sign(key: ByteArray, data: ByteArray, algorithm: HmacAlgorithm): ByteArray {
        val mac = Mac.getInstance(algorithm.algorithmName)
        mac.init(SecretKeySpec(key, algorithm.algorithmName))
        return mac.doFinal(data)
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
