@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.wannaverse.crypto.asymmetric.ecdsa

import com.wannaverse.crypto.asymmetric.util.DerUtils
import com.wannaverse.crypto.asymmetric.util.SecKeyHelper
import platform.CoreFoundation.CFRelease
import platform.Security.*

actual object ECDSA {

    actual fun generateKeyPair(curve: ECDSACurve): ECDSAKeyPair {
        val (privRef, pubRef) = SecKeyHelper.generateKeyPair(
            kSecAttrKeyTypeECSECPrimeRandom, curve.keySize
        )

        // Export raw keys from SecKey
        // Public: uncompressed point (04||X||Y)
        // Private: (04||X||Y||D) concatenation
        val rawPublic = SecKeyHelper.exportKey(pubRef)
        val rawPrivate = SecKeyHelper.exportKey(privRef)

        CFRelease(privRef)
        CFRelease(pubRef)

        val curveOid = DerUtils.curveOidForName(curve.curveName)
        val algId = DerUtils.ecAlgorithmIdentifier(curveOid)

        // Wrap public key in X.509 format
        val x509Public = DerUtils.wrapInX509(rawPublic, algId)

        // Extract private scalar and build SEC1, then wrap in PKCS8
        val pointSize = rawPublic.size // 04||X||Y
        val privateScalar = rawPrivate.copyOfRange(pointSize, rawPrivate.size)
        val sec1 = DerUtils.buildSec1EcPrivateKey(privateScalar, curveOid, rawPublic)
        val pkcs8Private = DerUtils.wrapInPkcs8(sec1, algId)

        return ECDSAKeyPair(
            publicKey = x509Public,
            privateKey = pkcs8Private,
            curve = curve
        )
    }

    actual fun sign(privateKey: ByteArray, data: ByteArray, curve: ECDSACurve): ByteArray {
        val rawKey = importPrivateKey(privateKey, curve)
        val keyRef = SecKeyHelper.createSecKey(
            rawKey, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPrivate, curve.keySize
        )

        val result = SecKeyHelper.sign(keyRef, signatureAlgorithm(curve), data)
        CFRelease(keyRef)
        return result // DER-encoded, matching the expect API contract
    }

    actual fun verify(
        publicKey: ByteArray,
        data: ByteArray,
        signature: ByteArray,
        curve: ECDSACurve
    ): Boolean {
        // Extract raw point from X.509
        val rawPoint = DerUtils.stripX509Header(publicKey)
        val keyRef = SecKeyHelper.createSecKey(
            rawPoint, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic, curve.keySize
        )

        val result = SecKeyHelper.verify(keyRef, signatureAlgorithm(curve), data, signature)
        CFRelease(keyRef)
        return result
    }

    /**
     * Converts a PKCS8-encoded EC private key to the raw format expected by iOS SecKey.
     * iOS format: (04||X||Y||D) — the uncompressed public point concatenated with the private scalar.
     */
    private fun importPrivateKey(pkcs8Key: ByteArray, curve: ECDSACurve): ByteArray {
        // PKCS8 → SEC1
        val sec1 = DerUtils.stripPkcs8Header(pkcs8Key)

        // SEC1 → raw scalar + public point
        val (privateScalar, publicPoint) = DerUtils.parseSec1EcPrivateKey(sec1)

        if (publicPoint != null) {
            // iOS format: public point || private scalar
            // Pad the scalar to the expected component length
            val paddedScalar = padToLength(privateScalar, curve.componentLength)
            return publicPoint + paddedScalar
        }

        throw RuntimeException("EC private key does not contain public point; cannot import to iOS")
    }

    private fun signatureAlgorithm(curve: ECDSACurve): SecKeyAlgorithm? = when (curve) {
        ECDSACurve.P256 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA256
        ECDSACurve.P384 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA384
        ECDSACurve.P521 -> kSecKeyAlgorithmECDSASignatureMessageX962SHA512
    }

    private fun padToLength(data: ByteArray, length: Int): ByteArray {
        return if (data.size >= length) {
            data.copyOfRange(data.size - length, data.size)
        } else {
            ByteArray(length - data.size) + data
        }
    }
}
