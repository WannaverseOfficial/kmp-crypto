package com.wannaverse.crypto.hashing

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

actual class Argon2 actual constructor() {

    actual fun hash(password: ByteArray, salt: ByteArray, config: com.wannaverse.crypto.kdf.argon2.Argon2Config): ByteArray {
        val type = when (config.type) {
            com.wannaverse.crypto.kdf.argon2.Argon2Type.Argon2d -> Argon2Parameters.ARGON2_d
            com.wannaverse.crypto.kdf.argon2.Argon2Type.Argon2i -> Argon2Parameters.ARGON2_i
            com.wannaverse.crypto.kdf.argon2.Argon2Type.Argon2id -> Argon2Parameters.ARGON2_id
        }

        val params = Argon2Parameters.Builder(type)
            .withSalt(salt)
            .withParallelism(config.parallelism)
            .withMemoryAsKB(config.memorySizeKB)
            .withIterations(config.iterations)
            .build()

        val generator = Argon2BytesGenerator()
        generator.init(params)

        val result = ByteArray(config.hashLength)
        generator.generateBytes(password, result)
        return result
    }
}
