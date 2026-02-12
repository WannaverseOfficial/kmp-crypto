package com.wannaverse.crypto.jwt

/**
 * Sealed class representing JWT signing algorithms.
 *
 * Each subclass carries the key material needed for signing or verification.
 * For HMAC algorithms, provide the shared secret.
 * For asymmetric algorithms, provide the private key for signing and/or the public key for verification.
 *
 * @property algorithmName The algorithm identifier used in the JWT header "alg" field.
 */
sealed class JwtAlgorithm(val algorithmName: String) {

    // HMAC family
    class HS256(val secret: ByteArray) : JwtAlgorithm("HS256")
    class HS384(val secret: ByteArray) : JwtAlgorithm("HS384")
    class HS512(val secret: ByteArray) : JwtAlgorithm("HS512")

    // RSA PKCS#1 v1.5 family
    class RS256(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("RS256")
    class RS384(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("RS384")
    class RS512(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("RS512")

    // RSA PSS family
    class PS256(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("PS256")
    class PS384(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("PS384")
    class PS512(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("PS512")

    // ECDSA family
    class ES256(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("ES256")
    class ES384(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("ES384")
    class ES512(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("ES512")

    // EdDSA
    class EdDSA(val privateKey: ByteArray? = null, val publicKey: ByteArray? = null) : JwtAlgorithm("EdDSA")
}
