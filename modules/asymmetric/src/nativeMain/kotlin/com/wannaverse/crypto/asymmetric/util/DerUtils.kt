package com.wannaverse.crypto.asymmetric.util

/**
 * ASN.1 DER parsing and key format conversion utilities.
 *
 * Converts between Java-style key formats (X.509 SubjectPublicKeyInfo / PKCS8 PrivateKeyInfo)
 * and iOS-style raw key formats (PKCS1 for RSA, raw point for EC, raw bytes for Ed25519).
 */
internal object DerUtils {

    // --- DER length encoding/decoding ---

    fun readDerLength(data: ByteArray, offset: Int): Pair<Int, Int> {
        val first = data[offset].toInt() and 0xFF
        if (first < 0x80) return first to 1
        val numBytes = first and 0x7F
        var length = 0
        for (i in 1..numBytes) {
            length = (length shl 8) or (data[offset + i].toInt() and 0xFF)
        }
        return length to (1 + numBytes)
    }

    fun encodeDerLength(length: Int): ByteArray = when {
        length < 0x80 -> byteArrayOf(length.toByte())
        length < 0x100 -> byteArrayOf(0x81.toByte(), length.toByte())
        length < 0x10000 -> byteArrayOf(
            0x82.toByte(),
            (length shr 8).toByte(),
            (length and 0xFF).toByte()
        )
        else -> byteArrayOf(
            0x83.toByte(),
            (length shr 16).toByte(),
            ((length shr 8) and 0xFF).toByte(),
            (length and 0xFF).toByte()
        )
    }

    /** Skip a TLV at offset, return the offset after the TLV. */
    fun skipTlv(data: ByteArray, offset: Int): Int {
        var pos = offset + 1
        val (len, lenSize) = readDerLength(data, pos)
        return pos + lenSize + len
    }

    /** Extract content bytes from TLV at offset. Returns (content, offsetAfterTLV). */
    fun extractTlvContent(data: ByteArray, offset: Int): Pair<ByteArray, Int> {
        var pos = offset + 1
        val (len, lenSize) = readDerLength(data, pos)
        pos += lenSize
        return data.copyOfRange(pos, pos + len) to (pos + len)
    }

    // --- X.509 SubjectPublicKeyInfo operations ---

    /**
     * Strips the X.509 SubjectPublicKeyInfo wrapper.
     * Returns the raw key inside the BIT STRING:
     * - RSA: PKCS1 public key
     * - EC: uncompressed point (04||X||Y)
     * - Ed25519: raw 32-byte public key
     */
    fun stripX509Header(x509Key: ByteArray): ByteArray {
        var offset = 0

        // Outer SEQUENCE
        require((x509Key[offset].toInt() and 0xFF) == 0x30) { "Expected SEQUENCE" }
        offset++
        val (_, outerLenSize) = readDerLength(x509Key, offset)
        offset += outerLenSize

        // AlgorithmIdentifier SEQUENCE — skip
        require((x509Key[offset].toInt() and 0xFF) == 0x30) { "Expected AlgorithmIdentifier SEQUENCE" }
        offset = skipTlv(x509Key, offset)

        // BIT STRING containing the key
        require((x509Key[offset].toInt() and 0xFF) == 0x03) { "Expected BIT STRING" }
        offset++
        val (bitStringLen, bitStringLenSize) = readDerLength(x509Key, offset)
        offset += bitStringLenSize
        offset++ // skip unused-bits byte (0x00)

        return x509Key.copyOfRange(offset, offset + bitStringLen - 1)
    }

    /**
     * Strips the PKCS8 PrivateKeyInfo wrapper.
     * Returns the key inside the OCTET STRING:
     * - RSA: PKCS1 private key
     * - EC: SEC1 EC private key
     * - Ed25519: inner OCTET STRING containing 32-byte seed
     */
    fun stripPkcs8Header(pkcs8Key: ByteArray): ByteArray {
        var offset = 0

        // Outer SEQUENCE
        require((pkcs8Key[offset].toInt() and 0xFF) == 0x30) { "Expected SEQUENCE" }
        offset++
        val (_, outerLenSize) = readDerLength(pkcs8Key, offset)
        offset += outerLenSize

        // Version INTEGER — skip
        require((pkcs8Key[offset].toInt() and 0xFF) == 0x02) { "Expected version INTEGER" }
        offset = skipTlv(pkcs8Key, offset)

        // AlgorithmIdentifier SEQUENCE — skip
        require((pkcs8Key[offset].toInt() and 0xFF) == 0x30) { "Expected AlgorithmIdentifier SEQUENCE" }
        offset = skipTlv(pkcs8Key, offset)

        // OCTET STRING containing the key
        require((pkcs8Key[offset].toInt() and 0xFF) == 0x04) { "Expected OCTET STRING" }
        val (content, _) = extractTlvContent(pkcs8Key, offset)
        return content
    }

    /**
     * Strips the extra OCTET STRING wrapping from an Ed25519 PKCS8 private key.
     * PKCS8 Ed25519: SEQUENCE { INT(0), SEQ{OID}, OCTET STRING { OCTET STRING { 32-byte seed } } }
     * After stripPkcs8Header, we get OCTET STRING { 32-byte seed }. This strips that final wrapper.
     */
    fun stripEd25519PrivateKey(pkcs8Key: ByteArray): ByteArray {
        val inner = stripPkcs8Header(pkcs8Key)
        // inner is OCTET STRING { 32-byte seed }
        require((inner[0].toInt() and 0xFF) == 0x04) { "Expected inner OCTET STRING for Ed25519" }
        val (seed, _) = extractTlvContent(inner, 0)
        return seed
    }

    // --- Wrapping operations ---

    /** Wraps raw key bytes in X.509 SubjectPublicKeyInfo format. */
    fun wrapInX509(rawKey: ByteArray, algorithmIdentifier: ByteArray): ByteArray {
        // BIT STRING = 0x03 + length + 0x00 (unused bits) + rawKey
        val bitString = byteArrayOf(0x03) + encodeDerLength(rawKey.size + 1) + byteArrayOf(0x00) + rawKey

        // Outer SEQUENCE = 0x30 + length + algorithmIdentifier + bitString
        val content = algorithmIdentifier + bitString
        return byteArrayOf(0x30) + encodeDerLength(content.size) + content
    }

    /** Wraps raw key bytes in PKCS8 PrivateKeyInfo format. */
    fun wrapInPkcs8(innerKey: ByteArray, algorithmIdentifier: ByteArray): ByteArray {
        val version = byteArrayOf(0x02, 0x01, 0x00)
        val octetString = byteArrayOf(0x04) + encodeDerLength(innerKey.size) + innerKey
        val content = version + algorithmIdentifier + octetString
        return byteArrayOf(0x30) + encodeDerLength(content.size) + content
    }

    /** Wraps Ed25519 raw 32-byte seed in PKCS8 format (with inner OCTET STRING). */
    fun wrapEd25519PrivateKey(seed: ByteArray): ByteArray {
        // Inner: OCTET STRING { seed }
        val innerOctet = byteArrayOf(0x04) + encodeDerLength(seed.size) + seed
        return wrapInPkcs8(innerOctet, ED25519_ALGORITHM_IDENTIFIER)
    }

    /** Wraps Ed25519 raw 32-byte public key in X.509 format. */
    fun wrapEd25519PublicKey(publicKey: ByteArray): ByteArray {
        return wrapInX509(publicKey, ED25519_ALGORITHM_IDENTIFIER)
    }

    // --- EC-specific operations ---

    /**
     * Parses a SEC1 EC private key to extract the raw private scalar and optional public point.
     * SEC1: SEQUENCE { INTEGER(1), OCTET STRING(D), [0] OID(curve), [1] BIT STRING(publicKey) }
     */
    fun parseSec1EcPrivateKey(sec1Key: ByteArray): Pair<ByteArray, ByteArray?> {
        var offset = 0

        // SEQUENCE
        require((sec1Key[offset].toInt() and 0xFF) == 0x30)
        offset++
        val (_, seqLenSize) = readDerLength(sec1Key, offset)
        offset += seqLenSize

        // Version INTEGER(1) — skip
        require((sec1Key[offset].toInt() and 0xFF) == 0x02)
        offset = skipTlv(sec1Key, offset)

        // Private key scalar OCTET STRING
        require((sec1Key[offset].toInt() and 0xFF) == 0x04)
        val (privateScalar, nextOffset) = extractTlvContent(sec1Key, offset)
        offset = nextOffset

        // Look for [1] context tag containing public key
        var publicPoint: ByteArray? = null
        while (offset < sec1Key.size) {
            val tag = sec1Key[offset].toInt() and 0xFF
            if (tag == 0xA1) { // [1] EXPLICIT
                offset++
                val (_, explLenSize) = readDerLength(sec1Key, offset)
                offset += explLenSize
                // Inside: BIT STRING
                require((sec1Key[offset].toInt() and 0xFF) == 0x03)
                offset++
                val (bitLen, bitLenSize) = readDerLength(sec1Key, offset)
                offset += bitLenSize
                offset++ // skip unused bits byte
                publicPoint = sec1Key.copyOfRange(offset, offset + bitLen - 1)
                break
            } else {
                offset = skipTlv(sec1Key, offset)
            }
        }

        return privateScalar to publicPoint
    }

    /**
     * Builds a SEC1 EC private key structure from raw components.
     */
    fun buildSec1EcPrivateKey(
        privateScalar: ByteArray,
        curveOid: ByteArray,
        publicPoint: ByteArray
    ): ByteArray {
        val version = byteArrayOf(0x02, 0x01, 0x01)
        val privOctet = byteArrayOf(0x04) + encodeDerLength(privateScalar.size) + privateScalar
        val curveTag = byteArrayOf(0xA0.toByte()) + encodeDerLength(curveOid.size) + curveOid
        val pubBitString =
            byteArrayOf(0x03) + encodeDerLength(publicPoint.size + 1) + byteArrayOf(0x00) + publicPoint
        val pubTag = byteArrayOf(0xA1.toByte()) + encodeDerLength(pubBitString.size) + pubBitString
        val content = version + privOctet + curveTag + pubTag
        return byteArrayOf(0x30) + encodeDerLength(content.size) + content
    }

    // --- Known Algorithm Identifiers ---

    /** RSA AlgorithmIdentifier: SEQUENCE { OID(1.2.840.113549.1.1.1), NULL } */
    val RSA_ALGORITHM_IDENTIFIER = byteArrayOf(
        0x30, 0x0D,
        0x06, 0x09, 0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01,
        0x05, 0x00
    )

    /** Ed25519 AlgorithmIdentifier: SEQUENCE { OID(1.3.101.112) } */
    val ED25519_ALGORITHM_IDENTIFIER = byteArrayOf(
        0x30, 0x05,
        0x06, 0x03, 0x2B, 0x65, 0x70
    )

    // EC curve OIDs
    val EC_P256_OID = byteArrayOf(0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07)
    val EC_P384_OID = byteArrayOf(0x06, 0x05, 0x2B, 0x81.toByte(), 0x04, 0x00, 0x22)
    val EC_P521_OID = byteArrayOf(0x06, 0x05, 0x2B, 0x81.toByte(), 0x04, 0x00, 0x23)

    /** EC OID for ecPublicKey (1.2.840.10045.2.1) */
    private val EC_PUBLIC_KEY_OID = byteArrayOf(0x06, 0x07, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01)

    /** Build EC AlgorithmIdentifier: SEQUENCE { OID(ecPublicKey), OID(curve) } */
    fun ecAlgorithmIdentifier(curveOid: ByteArray): ByteArray {
        val content = EC_PUBLIC_KEY_OID + curveOid
        return byteArrayOf(0x30) + encodeDerLength(content.size) + content
    }

    fun curveOidForName(curveName: String): ByteArray = when (curveName) {
        "secp256r1" -> EC_P256_OID
        "secp384r1" -> EC_P384_OID
        "secp521r1" -> EC_P521_OID
        else -> throw IllegalArgumentException("Unknown curve: $curveName")
    }
}
