package com.wannaverse.crypto.core

object Base64 {
    private const val BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun toBase64(bytes: ByteArray): String {
        val result = StringBuilder()
        for (i in bytes.indices step 3) {
            val b1 = bytes[i].toInt() and 0xFF
            val b2 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
            val b3 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
            result.append(BASE64_ALPHABET[b1 shr 2])
            result.append(BASE64_ALPHABET[(b1 shl 4 or (b2 shr 4)) and 0x3F])
            if (i + 1 < bytes.size) result.append(BASE64_ALPHABET[(b2 shl 2 or (b3 shr 6)) and 0x3F])
            if (i + 2 < bytes.size) result.append(BASE64_ALPHABET[b3 and 0x3F])
        }
        return result.toString()
    }

    fun toBase64UrlSafe(bytes: ByteArray): String =
        toBase64(bytes).replace('+', '-').replace('/', '_').trimEnd('=')

    fun fromBase64(base64: String): ByteArray {
        val cleanInput = base64.replace("[-_]", "+").replace("=", "")
        val result = mutableListOf<Byte>()
        var i = 0
        while (i < cleanInput.length) {
            val c1 = BASE64_ALPHABET.indexOf(cleanInput[i])
            val c2 = if (i + 1 < cleanInput.length) BASE64_ALPHABET.indexOf(cleanInput[i + 1]) else 0
            val c3 = if (i + 2 < cleanInput.length) BASE64_ALPHABET.indexOf(cleanInput[i + 2]) else 0
            val c4 = if (i + 3 < cleanInput.length) BASE64_ALPHABET.indexOf(cleanInput[i + 3]) else 0
            result.add((c1 shl 2 or (c2 shr 4)).toByte())
            if (i + 2 < cleanInput.length) result.add(((c2 shl 4) or (c3 shr 2)).toByte())
            if (i + 3 < cleanInput.length) result.add(((c3 shl 6) or c4).toByte())
            i += 4
        }
        return result.toByteArray()
    }
}