package com.wannaverse.crypto.asymmetric.rsa

enum class RSAPadding(val paddingString: String) {
    PKCS1("RSA/ECB/PKCS1Padding"),
    OAEP_SHA1("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
    OAEP_SHA256("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
}