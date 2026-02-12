package com.wannaverse.crypto.jwt

import com.wannaverse.crypto.asymmetric.ecdsa.ECDSA
import com.wannaverse.crypto.asymmetric.ecdsa.ECDSACurve
import com.wannaverse.crypto.asymmetric.ed25519.ED25519
import com.wannaverse.crypto.asymmetric.rsa.RSA
import com.wannaverse.crypto.asymmetric.rsa.RSASignaturePadding
import com.wannaverse.crypto.hashing.HMAC
import com.wannaverse.crypto.hashing.HmacAlgorithm

/**
 * Internal utility that dispatches JWT signing and verification
 * to the appropriate cryptographic primitives.
 */
internal object JwtSigner {

    fun sign(data: ByteArray, algorithm: JwtAlgorithm): ByteArray = when (algorithm) {
        is JwtAlgorithm.HS256 -> HMAC.sign(algorithm.secret, data, HmacAlgorithm.HMAC_SHA256)
        is JwtAlgorithm.HS384 -> HMAC.sign(algorithm.secret, data, HmacAlgorithm.HMAC_SHA384)
        is JwtAlgorithm.HS512 -> HMAC.sign(algorithm.secret, data, HmacAlgorithm.HMAC_SHA512)

        is JwtAlgorithm.RS256 -> RSA.sign(requireKey(algorithm.privateKey, "RS256"), data, RSASignaturePadding.PKCS1_SHA256)
        is JwtAlgorithm.RS384 -> RSA.sign(requireKey(algorithm.privateKey, "RS384"), data, RSASignaturePadding.PKCS1_SHA384)
        is JwtAlgorithm.RS512 -> RSA.sign(requireKey(algorithm.privateKey, "RS512"), data, RSASignaturePadding.PKCS1_SHA512)

        is JwtAlgorithm.PS256 -> RSA.sign(requireKey(algorithm.privateKey, "PS256"), data, RSASignaturePadding.PSS_SHA256)
        is JwtAlgorithm.PS384 -> RSA.sign(requireKey(algorithm.privateKey, "PS384"), data, RSASignaturePadding.PSS_SHA384)
        is JwtAlgorithm.PS512 -> RSA.sign(requireKey(algorithm.privateKey, "PS512"), data, RSASignaturePadding.PSS_SHA512)

        is JwtAlgorithm.ES256 -> derToRawSignature(
            ECDSA.sign(requireKey(algorithm.privateKey, "ES256"), data, ECDSACurve.P256),
            ECDSACurve.P256.componentLength
        )
        is JwtAlgorithm.ES384 -> derToRawSignature(
            ECDSA.sign(requireKey(algorithm.privateKey, "ES384"), data, ECDSACurve.P384),
            ECDSACurve.P384.componentLength
        )
        is JwtAlgorithm.ES512 -> derToRawSignature(
            ECDSA.sign(requireKey(algorithm.privateKey, "ES512"), data, ECDSACurve.P521),
            ECDSACurve.P521.componentLength
        )

        is JwtAlgorithm.EdDSA -> ED25519.sign(requireKey(algorithm.privateKey, "EdDSA"), data)
    }

    fun verify(data: ByteArray, signature: ByteArray, algorithm: JwtAlgorithm): Boolean = when (algorithm) {
        is JwtAlgorithm.HS256 -> HMAC.verify(algorithm.secret, data, signature, HmacAlgorithm.HMAC_SHA256)
        is JwtAlgorithm.HS384 -> HMAC.verify(algorithm.secret, data, signature, HmacAlgorithm.HMAC_SHA384)
        is JwtAlgorithm.HS512 -> HMAC.verify(algorithm.secret, data, signature, HmacAlgorithm.HMAC_SHA512)

        is JwtAlgorithm.RS256 -> RSA.verify(requireKey(algorithm.publicKey, "RS256"), signature, data, RSASignaturePadding.PKCS1_SHA256)
        is JwtAlgorithm.RS384 -> RSA.verify(requireKey(algorithm.publicKey, "RS384"), signature, data, RSASignaturePadding.PKCS1_SHA384)
        is JwtAlgorithm.RS512 -> RSA.verify(requireKey(algorithm.publicKey, "RS512"), signature, data, RSASignaturePadding.PKCS1_SHA512)

        is JwtAlgorithm.PS256 -> RSA.verify(requireKey(algorithm.publicKey, "PS256"), signature, data, RSASignaturePadding.PSS_SHA256)
        is JwtAlgorithm.PS384 -> RSA.verify(requireKey(algorithm.publicKey, "PS384"), signature, data, RSASignaturePadding.PSS_SHA384)
        is JwtAlgorithm.PS512 -> RSA.verify(requireKey(algorithm.publicKey, "PS512"), signature, data, RSASignaturePadding.PSS_SHA512)

        is JwtAlgorithm.ES256 -> ECDSA.verify(
            requireKey(algorithm.publicKey, "ES256"), data,
            rawToDerSignature(signature, ECDSACurve.P256.componentLength), ECDSACurve.P256
        )
        is JwtAlgorithm.ES384 -> ECDSA.verify(
            requireKey(algorithm.publicKey, "ES384"), data,
            rawToDerSignature(signature, ECDSACurve.P384.componentLength), ECDSACurve.P384
        )
        is JwtAlgorithm.ES512 -> ECDSA.verify(
            requireKey(algorithm.publicKey, "ES512"), data,
            rawToDerSignature(signature, ECDSACurve.P521.componentLength), ECDSACurve.P521
        )

        is JwtAlgorithm.EdDSA -> ED25519.verify(requireKey(algorithm.publicKey, "EdDSA"), data, signature)
    }

    private fun requireKey(key: ByteArray?, algorithmName: String): ByteArray =
        key ?: throw JwtException("Key required for $algorithmName")
}
