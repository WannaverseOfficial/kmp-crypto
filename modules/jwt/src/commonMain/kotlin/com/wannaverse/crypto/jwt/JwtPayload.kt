package com.wannaverse.crypto.jwt

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * Represents the JWT payload (claims set).
 *
 * Provides typed accessors for registered claims (RFC 7519 Section 4.1)
 * and methods for custom claims.
 */
class JwtPayload(
    private val claims: MutableMap<String, JsonElement> = mutableMapOf()
) {
    // --- Registered claims (RFC 7519 Section 4.1) ---

    /** Issuer (iss) claim. */
    var issuer: String?
        get() = claims["iss"]?.jsonPrimitive?.contentOrNull
        set(value) { setClaim("iss", value) }

    /** Subject (sub) claim. */
    var subject: String?
        get() = claims["sub"]?.jsonPrimitive?.contentOrNull
        set(value) { setClaim("sub", value) }

    /** Audience (aud) claim. */
    var audience: String?
        get() = claims["aud"]?.jsonPrimitive?.contentOrNull
        set(value) { setClaim("aud", value) }

    /** Expiration time (exp) claim as epoch seconds. */
    var expiresAt: Long?
        get() = claims["exp"]?.jsonPrimitive?.longOrNull
        set(value) { setClaim("exp", value) }

    /** Not before (nbf) claim as epoch seconds. */
    var notBefore: Long?
        get() = claims["nbf"]?.jsonPrimitive?.longOrNull
        set(value) { setClaim("nbf", value) }

    /** Issued at (iat) claim as epoch seconds. */
    var issuedAt: Long?
        get() = claims["iat"]?.jsonPrimitive?.longOrNull
        set(value) { setClaim("iat", value) }

    /** JWT ID (jti) claim. */
    var jwtId: String?
        get() = claims["jti"]?.jsonPrimitive?.contentOrNull
        set(value) { setClaim("jti", value) }

    // Custom claims

    fun claim(name: String, value: String) { claims[name] = JsonPrimitive(value) }
    fun claim(name: String, value: Long) { claims[name] = JsonPrimitive(value) }
    fun claim(name: String, value: Boolean) { claims[name] = JsonPrimitive(value) }
    fun claim(name: String, value: JsonElement) { claims[name] = value }

    fun getClaim(name: String): JsonElement? = claims[name]
    fun getStringClaim(name: String): String? = claims[name]?.jsonPrimitive?.contentOrNull
    fun getLongClaim(name: String): Long? = claims[name]?.jsonPrimitive?.longOrNull
    fun getBooleanClaim(name: String): Boolean? = claims[name]?.jsonPrimitive?.booleanOrNull

    fun getAllClaims(): Map<String, JsonElement> = claims.toMap()

    fun toJson(): String = Json.encodeToString(JsonObject.serializer(), JsonObject(claims))

    private fun setClaim(name: String, value: String?) {
        if (value != null) claims[name] = JsonPrimitive(value) else claims.remove(name)
    }

    private fun setClaim(name: String, value: Long?) {
        if (value != null) claims[name] = JsonPrimitive(value) else claims.remove(name)
    }

    companion object {
        private val jsonCodec = Json { ignoreUnknownKeys = true }

        fun fromJson(json: String): JwtPayload {
            val jsonObject = jsonCodec.decodeFromString(JsonObject.serializer(), json)
            return JwtPayload(jsonObject.toMutableMap())
        }
    }
}
