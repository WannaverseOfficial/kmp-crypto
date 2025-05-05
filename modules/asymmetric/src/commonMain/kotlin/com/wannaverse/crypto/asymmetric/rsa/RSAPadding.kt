package com.wannaverse.crypto.asymmetric.rsa

/**
 * Enum class representing RSA encryption padding schemes.
 *
 * These paddings are used during RSA encryption and decryption to enhance security.
 *
 * @property paddingString The transformation string used by cryptographic providers to identify the padding scheme.
 */
enum class RSAPadding(val paddingString: String) {
    /**
     * PKCS#1 v1.5 padding scheme.
     * Commonly used and widely supported, though less secure than OAEP for new applications.
     */
    PKCS1("RSA/ECB/PKCS1Padding"),

    /**
     * OAEP (Optimal Asymmetric Encryption Padding) with SHA-1.
     * Offers better security properties than PKCS1.
     */
    OAEP_SHA1("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),

    /**
     * OAEP (Optimal Asymmetric Encryption Padding) with SHA-256.
     * A stronger variant of OAEP with a modern hash function, recommended for new systems.
     */
    OAEP_SHA256("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
}