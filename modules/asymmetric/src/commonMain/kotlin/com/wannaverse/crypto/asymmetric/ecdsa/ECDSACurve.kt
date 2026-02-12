package com.wannaverse.crypto.asymmetric.ecdsa

/**
 * Enum representing supported ECDSA curves.
 *
 * @property curveName The standard curve name used by cryptographic providers.
 * @property keySize The key size in bits.
 * @property componentLength The byte length of each R and S signature component.
 */
enum class ECDSACurve(val curveName: String, val keySize: Int, val componentLength: Int) {
    P256("secp256r1", 256, 32),
    P384("secp384r1", 384, 48),
    P521("secp521r1", 521, 66)
}
