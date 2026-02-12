package com.wannaverse.crypto.jwt

import com.wannaverse.crypto.core.Base64

/**
 * Main entry point for JWT operations.
 *
 * Provides a fluent API for creating, verifying, and decoding JWTs.
 *
 * ## Creating a JWT
 * ```
 * val token = JWT.create()
 *     .withIssuer("auth.example.com")
 *     .withSubject("user123")
 *     .withClaim("role", "admin")
 *     .withExpiresAt(epochSeconds + 3600)
 *     .sign(JwtAlgorithm.HS256(secretKey))
 * ```
 *
 * ## Verifying a JWT
 * ```
 * val decoded = JWT.verify(token, JwtAlgorithm.HS256(secretKey))
 * println(decoded.payload.subject) // "user123"
 * ```
 *
 * ## Verifying with claims validation
 * ```
 * val decoded = JWT.verifier(JwtAlgorithm.RS256(publicKey = rsaPubKey))
 *     .withIssuer("auth.example.com")
 *     .verify(token)
 * ```
 *
 * ## Decoding without verification
 * ```
 * val unverified = JWT.decode(token)
 * println(unverified.header.alg)
 * ```
 */
object JWT {

    /**
     * Creates a new JWT builder.
     */
    fun create(): JwtBuilder = JwtBuilder()

    /**
     * Creates a verifier for the given algorithm with optional leeway.
     *
     * @param algorithm The algorithm and key material to use for verification.
     * @param leewaySeconds Clock skew tolerance in seconds for time-based claims.
     */
    fun verifier(algorithm: JwtAlgorithm, leewaySeconds: Long = 0): JwtVerifier =
        JwtVerifier(algorithm, leewaySeconds)

    /**
     * Verifies a JWT and returns the decoded result.
     *
     * @param token The JWT compact serialization string.
     * @param algorithm The algorithm and key material to use for verification.
     * @return The decoded JWT if verification succeeds.
     * @throws JwtSignatureException if the signature is invalid.
     * @throws JwtExpiredException if the token has expired.
     * @throws JwtException for other validation failures.
     */
    fun verify(token: String, algorithm: JwtAlgorithm): DecodedJwt =
        JwtVerifier(algorithm).verify(token)

    /**
     * Decodes a JWT without verifying the signature.
     *
     * Useful for inspecting the header (e.g., to determine the algorithm or key ID)
     * before choosing a key for verification.
     *
     * @param token The JWT compact serialization string.
     * @return The decoded JWT (unverified).
     * @throws JwtException if the token format is invalid.
     */
    fun decode(token: String): DecodedJwt {
        val parts = token.split(".")
        if (parts.size != 3) throw JwtException("Invalid JWT format: expected 3 parts, got ${parts.size}")

        val header = JwtHeader.fromJson(Base64.fromBase64(parts[0]).decodeToString())
        val payload = JwtPayload.fromJson(Base64.fromBase64(parts[1]).decodeToString())
        val signature = Base64.fromBase64(parts[2])

        return DecodedJwt(header, payload, signature, token)
    }
}
