package com.wannaverse.crypto.jwt

/**
 * Base exception for JWT-related errors.
 */
open class JwtException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Thrown when a JWT has expired (current time > exp + leeway).
 */
class JwtExpiredException(message: String = "Token has expired") : JwtException(message)

/**
 * Thrown when a JWT is not yet valid (current time < nbf - leeway).
 */
class JwtNotYetValidException(message: String = "Token is not yet valid") : JwtException(message)

/**
 * Thrown when a JWT signature is invalid.
 */
class JwtSignatureException(message: String = "Invalid signature") : JwtException(message)
