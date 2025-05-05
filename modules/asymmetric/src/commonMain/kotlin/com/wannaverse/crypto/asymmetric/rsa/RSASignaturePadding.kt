package com.wannaverse.crypto.asymmetric.rsa

/**
 * Enum class representing RSA signature padding schemes.
 *
 * These paddings define how data is processed during RSA signature generation and verification.
 *
 * @property signatureString The algorithm name used by cryptographic providers to specify the signature scheme.
 */
enum class RSASignaturePadding(val signatureString: String) {

    /**
     * PKCS#1 v1.5 padding with SHA-256.
     * A traditional and widely supported signature scheme. Suitable for interoperability.
     */
    PKCS1_SHA256("SHA256withRSA"),

    /**
     * RSASSA-PSS (Probabilistic Signature Scheme) with SHA-256.
     * A modern signature scheme that provides better security and is recommended for new applications.
     */
    PSS_SHA256("SHA256withRSA/PSS")
}
