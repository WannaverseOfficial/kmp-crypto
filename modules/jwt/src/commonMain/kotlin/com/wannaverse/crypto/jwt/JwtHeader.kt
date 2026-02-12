package com.wannaverse.crypto.jwt

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Represents the JWT header (JOSE header).
 *
 * @property alg The algorithm used to sign the token.
 * @property typ The token type, typically "JWT".
 * @property kid Optional key ID for identifying the signing key.
 */
@Serializable
data class JwtHeader(
    val alg: String,
    val typ: String = "JWT",
    val kid: String? = null
) {
    fun toJson(): String = jsonCodec.encodeToString(this)

    companion object {
        private val jsonCodec = Json { encodeDefaults = true; ignoreUnknownKeys = true }

        fun fromJson(json: String): JwtHeader = jsonCodec.decodeFromString(json)
    }
}
