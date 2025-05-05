package com.wannaverse.crypto.symmetric.aes

expect class AES() {
    fun encrypt(plaintext: ByteArray, key: ByteArray, config: AESConfig = AESConfig()): ByteArray
    fun decrypt(ciphertext: ByteArray, key: ByteArray, config: AESConfig = AESConfig()): ByteArray
    fun createKey(keySize: KeySize = KeySize.AES_256): ByteArray
}