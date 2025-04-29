package com.wannaverse.crypto.symmetric.aes

enum class AESMode(val cipherMode: String) {
    ECB("AES/ECB/PKCS5Padding"),
    CBC("AES/CBC/PKCS5Padding"),
    CFB("AES/CFB/NoPadding"),
    OFB("AES/OFB/NoPadding"),
    CTR("AES/CTR/NoPadding"),
    GCM("AES/GCM/NoPadding")
}