package com.wannaverse.crypto.symmetric.aes

data class AESConfig(
    val mode: AESMode = AESMode.GCM,
    val keySize: KeySize = KeySize.AES_256,
    val iv: ByteArray? = null,
    val aad: ByteArray? = null, // Additional Authenticated Data for GCM
    val tagLength: Int = 128 // Tag length in bits for GCM (96, 104, 112, 120, 128)
)