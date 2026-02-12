package com.wannaverse.crypto.jwt

/**
 * Represents a decoded JWT with its header, payload, and signature.
 *
 * @property header The decoded JWT header.
 * @property payload The decoded JWT payload (claims).
 * @property signature The raw signature bytes.
 * @property token The original token string.
 */
class DecodedJwt(
    val header: JwtHeader,
    val payload: JwtPayload,
    val signature: ByteArray,
    val token: String
)
