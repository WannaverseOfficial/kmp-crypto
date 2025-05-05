package com.wannaverse.crypto.symmetric.aes

import platform.CoreCrypto.*
import kotlinx.cinterop.*
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

actual class AES {

    @OptIn(ExperimentalForeignApi::class)
    actual fun encrypt(plaintext: ByteArray, key: ByteArray, config: AESConfig): ByteArray {
        require(key.size in arrayOf(16, 24, 32)) { "AES key must be 16, 24, or 32 bytes" }

        // Generate or use provided IV (16 bytes for AES CBC)
        val iv = config.iv ?: ByteArray(16).also { nextBytes(it) }

        require(iv.size == 16) { "IV must be 16 bytes for AES CBC" }

        // Prepare output buffer (plaintext size + block size for padding)
        val cipherTextSize = (plaintext.size.toUInt() + kCCBlockSizeAES128).toInt()
        val cipherText = ByteArray(cipherTextSize)
        val dataOutMoved = nativeHeap.alloc<ULongVar>()

        // Convert inputs to C-compatible pointers
        plaintext.usePinned { plaintextPinned ->
            key.usePinned { keyPinned ->
                iv.usePinned { ivPinned ->
                    cipherText.usePinned { cipherTextPinned ->
                        // Perform AES encryption using CoreCrypto
                        val cryptorRef = nativeHeap.alloc<CCCryptorRefVar>()
                        var status = CCCryptorCreate(
                            kCCEncrypt,
                            kCCAlgorithmAES,
                            kCCOptionPKCS7Padding,
                            keyPinned.addressOf(0),
                            key.size.toULong(),
                            ivPinned.addressOf(0),
                            cryptorRef.ptr
                        )

                        if (status != kCCSuccess) {
                            nativeHeap.free(cryptorRef)
                            throw IllegalStateException("Failed to create cryptor: $status")
                        }

                        // Encrypt the data
                        status = CCCryptorUpdate(
                            cryptorRef.value,
                            plaintextPinned.addressOf(0),
                            plaintext.size.toULong(),
                            cipherTextPinned.addressOf(0),
                            cipherTextSize.toULong(),
                            dataOutMoved.ptr
                        )

                        if (status != kCCSuccess) {
                            CCCryptorRelease(cryptorRef.value)
                            nativeHeap.free(cryptorRef)
                            throw IllegalStateException("Encryption update failed: $status")
                        }

                        // Finalize encryption (handle padding)
                        val finalDataMoved = nativeHeap.alloc<ULongVar>()
                        status = CCCryptorFinal(
                            cryptorRef.value,
                            cipherTextPinned.addressOf(dataOutMoved.value.toInt()),
                            (cipherTextSize - dataOutMoved.value.toInt()).toULong(),
                            finalDataMoved.ptr
                        )

                        if (status != kCCSuccess) {
                            CCCryptorRelease(cryptorRef.value)
                            nativeHeap.free(cryptorRef)
                            nativeHeap.free(finalDataMoved)
                            throw IllegalStateException("Encryption finalization failed: $status")
                        }

                        // Calculate total output size
                        val totalSize = dataOutMoved.value + finalDataMoved.value
                        CCCryptorRelease(cryptorRef.value)
                        nativeHeap.free(cryptorRef)
                        nativeHeap.free(finalDataMoved)
                        nativeHeap.free(dataOutMoved)

                        // Combine IV and ciphertext for output
                        return iv + cipherText.copyOf(totalSize.toInt())
                    }
                }
            }
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    actual fun decrypt(
        ciphertext: ByteArray,
        key: ByteArray,
        config: AESConfig
    ): ByteArray {
        // Validate inputs
        require(key.size in arrayOf(16, 24, 32)) { "AES key must be 16, 24, or 32 bytes" }
        require(ciphertext.size > 16) { "Ciphertext must include a 16-byte IV" }

        // Extract IV from the beginning of the ciphertext, unless explicitly provided
        val iv = config.iv ?: ciphertext.copyOfRange(0, 16)
        require(iv.size == 16) { "IV must be 16 bytes" }

        // The actual encrypted data is after the IV
        val encryptedData = if (config.iv == null) ciphertext.copyOfRange(16, ciphertext.size) else ciphertext

        // Prepare output buffer (same size as encrypted data should suffice)
        val plainText = ByteArray(encryptedData.size)
        val dataOutMoved = nativeHeap.alloc<ULongVar>()

        encryptedData.usePinned { encryptedPinned ->
            key.usePinned { keyPinned ->
                iv.usePinned { ivPinned ->
                    plainText.usePinned { plainTextPinned ->
                        val cryptorRef = nativeHeap.alloc<CCCryptorRefVar>()

                        // Create decryptor
                        var status = CCCryptorCreate(
                            kCCDecrypt,
                            kCCAlgorithmAES,
                            kCCOptionPKCS7Padding,
                            keyPinned.addressOf(0),
                            key.size.toULong(),
                            ivPinned.addressOf(0),
                            cryptorRef.ptr
                        )

                        if (status != kCCSuccess) {
                            nativeHeap.free(cryptorRef)
                            throw IllegalStateException("Failed to create decryptor: $status")
                        }

                        // Decrypt data
                        status = CCCryptorUpdate(
                            cryptorRef.value,
                            encryptedPinned.addressOf(0),
                            encryptedData.size.toULong(),
                            plainTextPinned.addressOf(0),
                            plainText.size.toULong(),
                            dataOutMoved.ptr
                        )

                        if (status != kCCSuccess) {
                            CCCryptorRelease(cryptorRef.value)
                            nativeHeap.free(cryptorRef)
                            throw IllegalStateException("Decryption update failed: $status")
                        }

                        val finalDataMoved = nativeHeap.alloc<ULongVar>()
                        status = CCCryptorFinal(
                            cryptorRef.value,
                            plainTextPinned.addressOf(dataOutMoved.value.toInt()),
                            (plainText.size - dataOutMoved.value.toInt()).toULong(),
                            finalDataMoved.ptr
                        )

                        if (status != kCCSuccess) {
                            CCCryptorRelease(cryptorRef.value)
                            nativeHeap.free(finalDataMoved)
                            nativeHeap.free(cryptorRef)
                            throw IllegalStateException("Decryption finalization failed: $status")
                        }

                        val totalSize = dataOutMoved.value + finalDataMoved.value
                        CCCryptorRelease(cryptorRef.value)
                        nativeHeap.free(dataOutMoved)
                        nativeHeap.free(finalDataMoved)
                        nativeHeap.free(cryptorRef)

                        return plainText.copyOf(totalSize.toInt())
                    }
                }
            }
        }
    }

    actual fun createKey(keySize: KeySize): ByteArray {
        return nextBytes(keySize.bits / 8)
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun nextBytes(length: Int): ByteArray {
        val result = ByteArray(length)
        result.usePinned {
            val status = SecRandomCopyBytes(kSecRandomDefault, length.toULong(), it.addressOf(0))
            if (status != 0) {
                throw RuntimeException("Failed to generate secure random bytes: $status")
            }
        }
        return result
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun nextBytes(array: ByteArray) {
        array.usePinned {
            val status = SecRandomCopyBytes(kSecRandomDefault, array.size.toULong(), it.addressOf(0))
            if (status != 0) {
                throw RuntimeException("Failed to generate secure random bytes: $status")
            }
        }
    }
}