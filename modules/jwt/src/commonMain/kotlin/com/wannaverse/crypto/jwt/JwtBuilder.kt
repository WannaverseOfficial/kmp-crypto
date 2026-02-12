package com.wannaverse.crypto.jwt

import com.wannaverse.crypto.core.Base64
import kotlinx.serialization.json.JsonElement

/**
 * Builder for constructing and signing JWTs.
 *
 * Usage:
 * ```
 * val token = JwtBuilder()
 *     .withIssuer("auth.example.com")
 *     .withSubject("user123")
 *     .withClaim("role", "admin")
 *     .withExpiresAt(System.currentTimeMillis() / 1000 + 3600)
 *     .sign(JwtAlgorithm.HS256(secretKey))
 * ```
 */
class JwtBuilder {
    private val payload = JwtPayload()
    private var keyId: String? = null

    fun withIssuer(issuer: String) = apply { payload.issuer = issuer }
    fun withSubject(subject: String) = apply { payload.subject = subject }
    fun withAudience(audience: String) = apply { payload.audience = audience }
    fun withExpiresAt(epochSeconds: Long) = apply { payload.expiresAt = epochSeconds }
    fun withNotBefore(epochSeconds: Long) = apply { payload.notBefore = epochSeconds }
    fun withIssuedAt(epochSeconds: Long) = apply { payload.issuedAt = epochSeconds }
    fun withJwtId(jti: String) = apply { payload.jwtId = jti }
    fun withKeyId(kid: String) = apply { keyId = kid }
    fun withClaim(name: String, value: String) = apply { payload.claim(name, value) }
    fun withClaim(name: String, value: Long) = apply { payload.claim(name, value) }
    fun withClaim(name: String, value: Boolean) = apply { payload.claim(name, value) }
    fun withClaim(name: String, value: JsonElement) = apply { payload.claim(name, value) }

    /**
     * Signs the JWT with the given algorithm and returns the compact serialization (header.payload.signature).
     *
     * @param algorithm The signing algorithm and key material.
     * @return The signed JWT as a compact string.
     */
    fun sign(algorithm: JwtAlgorithm): String {
        val header = JwtHeader(alg = algorithm.algorithmName, kid = keyId)
        val headerB64 = Base64.toBase64UrlSafe(header.toJson().encodeToByteArray())
        val payloadB64 = Base64.toBase64UrlSafe(payload.toJson().encodeToByteArray())
        val signingInput = "$headerB64.$payloadB64"
        val signature = JwtSigner.sign(signingInput.encodeToByteArray(), algorithm)
        val signatureB64 = Base64.toBase64UrlSafe(signature)
        return "$signingInput.$signatureB64"
    }
}
