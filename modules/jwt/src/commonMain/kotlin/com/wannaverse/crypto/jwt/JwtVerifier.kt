package com.wannaverse.crypto.jwt

import com.wannaverse.crypto.core.Base64

/**
 * Verifies JWT signatures and validates claims.
 *
 * Usage:
 * ```
 * val decoded = JwtVerifier(JwtAlgorithm.HS256(secretKey))
 *     .withIssuer("auth.example.com")
 *     .verify(token)
 * ```
 *
 * @param algorithm The algorithm and key material to use for verification.
 * @param leewaySeconds Clock skew tolerance in seconds for time-based claims (exp, nbf).
 */
class JwtVerifier(
    private val algorithm: JwtAlgorithm,
    private val leewaySeconds: Long = 0
) {
    private var expectedIssuer: String? = null
    private var expectedAudience: String? = null
    private var expectedSubject: String? = null

    fun withIssuer(issuer: String) = apply { expectedIssuer = issuer }
    fun withAudience(audience: String) = apply { expectedAudience = audience }
    fun withSubject(subject: String) = apply { expectedSubject = subject }

    /**
     * Verifies the token signature and validates claims.
     *
     * @param token The JWT compact serialization string.
     * @return The decoded JWT if verification succeeds.
     * @throws JwtSignatureException if the signature is invalid.
     * @throws JwtExpiredException if the token has expired.
     * @throws JwtNotYetValidException if the token is not yet valid.
     * @throws JwtException for other validation failures (format, algorithm mismatch, claims mismatch).
     */
    fun verify(token: String): DecodedJwt {
        val parts = token.split(".")
        if (parts.size != 3) throw JwtException("Invalid JWT format: expected 3 parts, got ${parts.size}")

        val headerJson = Base64.fromBase64(parts[0]).decodeToString()
        val payloadJson = Base64.fromBase64(parts[1]).decodeToString()
        val signatureBytes = Base64.fromBase64(parts[2])

        val header = JwtHeader.fromJson(headerJson)
        if (header.alg != algorithm.algorithmName) {
            throw JwtException("Algorithm mismatch: expected ${algorithm.algorithmName}, got ${header.alg}")
        }

        val signingInput = "${parts[0]}.${parts[1]}".encodeToByteArray()
        if (!JwtSigner.verify(signingInput, signatureBytes, algorithm)) {
            throw JwtSignatureException()
        }

        val payload = JwtPayload.fromJson(payloadJson)
        validateClaims(payload)

        return DecodedJwt(header, payload, signatureBytes, token)
    }

    private fun validateClaims(payload: JwtPayload) {
        val now = currentTimeSeconds()

        payload.expiresAt?.let { exp ->
            if (now > exp + leewaySeconds) throw JwtExpiredException()
        }
        payload.notBefore?.let { nbf ->
            if (now < nbf - leewaySeconds) throw JwtNotYetValidException()
        }
        expectedIssuer?.let { expected ->
            if (payload.issuer != expected) throw JwtException("Issuer mismatch: expected $expected, got ${payload.issuer}")
        }
        expectedAudience?.let { expected ->
            if (payload.audience != expected) throw JwtException("Audience mismatch: expected $expected, got ${payload.audience}")
        }
        expectedSubject?.let { expected ->
            if (payload.subject != expected) throw JwtException("Subject mismatch: expected $expected, got ${payload.subject}")
        }
    }
}
