package com.wannaverse.crypto.asymmetric.rsa

enum class RSASignaturePadding(val signatureString: String) {
    PKCS1_SHA256("SHA256withRSA"),
    PSS_SHA256("SHA256withRSA/PSS");
}