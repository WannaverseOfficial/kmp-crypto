@file:Suppress("FunctionName")

package com.wannaverse.crypto.asymmetric.ed25519

import com.wannaverse.crypto.hashing.sha512

/**
 * Internal pure-Kotlin Ed25519 curve operations following RFC 8032.
 * Field arithmetic uses LongArray(16) limbs, based on the TweetNaCl approach.
 */
internal object Ed25519Internals {

    // Curve constant d
    private val D = longArrayOf(
        0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
        0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
    )

    // 2 * d
    private val D2 = longArrayOf(
        0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
        0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
    )

    // Base point X coordinate
    private val X = longArrayOf(
        0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
        0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
    )

    // Base point Y coordinate
    private val Y = longArrayOf(
        0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
    )

    // sqrt(-1) mod p
    private val I = longArrayOf(
        0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
        0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
    )

    // Group order L
    private val L = longArrayOf(
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
    )

    private val gf0 = LongArray(16)
    private val gf1 = longArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    // ===== Field Arithmetic =====

    private fun car25519(o: LongArray) {
        for (i in 0..15) {
            o[i] += (1L shl 16)
            val c = o[i] shr 16
            o[(i + 1) and 15] += c - 1 + 37 * (c - 1) * (i / 15).toLong()
            o[i] -= c shl 16
        }
    }

    private fun sel25519(p: LongArray, q: LongArray, b: Int) {
        val c = (b - 1).toLong().inv()
        for (i in 0..15) {
            val t = c and (p[i] xor q[i])
            p[i] = p[i] xor t
            q[i] = q[i] xor t
        }
    }

    private fun pack25519(o: ByteArray, oOff: Int, n: LongArray) {
        val m = LongArray(16)
        val t = n.copyOf()
        car25519(t)
        car25519(t)
        car25519(t)
        for (j in 0..1) {
            m[0] = t[0] - 0xffed
            for (i in 1..14) {
                m[i] = t[i] - 0xffff - ((m[i - 1] shr 16) and 1)
                m[i - 1] = m[i - 1] and 0xffff
            }
            m[15] = t[15] - 0x7fff - ((m[14] shr 16) and 1)
            val b = (m[15] shr 16) and 1
            m[14] = m[14] and 0xffff
            sel25519(t, m, (1 - b).toInt())
        }
        for (i in 0..15) {
            o[oOff + 2 * i] = (t[i] and 0xff).toByte()
            o[oOff + 2 * i + 1] = (t[i] shr 8).toByte()
        }
    }

    private fun unpack25519(o: LongArray, n: ByteArray, nOff: Int = 0) {
        for (i in 0..15) {
            o[i] = (n[nOff + 2 * i].toLong() and 0xff) + ((n[nOff + 2 * i + 1].toLong() and 0xff) shl 8)
        }
        o[15] = o[15] and 0x7fff
    }

    private fun A(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0..15) o[i] = a[i] + b[i]
    }

    private fun Z(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0..15) o[i] = a[i] - b[i]
    }

    private fun M(o: LongArray, a: LongArray, b: LongArray) {
        val t = LongArray(31)
        for (i in 0..15) for (j in 0..15) t[i + j] += a[i] * b[j]
        for (i in 0..14) t[i] += 38 * t[i + 16]
        for (i in 0..15) o[i] = t[i]
        car25519(o)
        car25519(o)
    }

    private fun S(o: LongArray, a: LongArray) = M(o, a, a)

    private fun inv25519(o: LongArray, a: LongArray) {
        val c = a.copyOf()
        for (i in 253 downTo 0) {
            S(c, c)
            if (i != 2 && i != 4) M(c, c, a)
        }
        for (i in 0..15) o[i] = c[i]
    }

    private fun pow2523(o: LongArray, a: LongArray) {
        val c = a.copyOf()
        for (i in 250 downTo 0) {
            S(c, c)
            if (i != 1) M(c, c, a)
        }
        for (i in 0..15) o[i] = c[i]
    }

    private fun par25519(a: LongArray): Int {
        val d = ByteArray(32)
        pack25519(d, 0, a)
        return d[0].toInt() and 1
    }

    private fun neq25519(a: LongArray, b: LongArray): Boolean {
        val c = ByteArray(32)
        val d = ByteArray(32)
        pack25519(c, 0, a)
        pack25519(d, 0, b)
        return !c.contentEquals(d)
    }

    // ===== Point Operations =====
    // Points are represented as Array<LongArray> of size 4: [X, Y, Z, T]

    private fun newPoint(): Array<LongArray> = arrayOf(LongArray(16), LongArray(16), LongArray(16), LongArray(16))

    private fun set(p: Array<LongArray>, q: Array<LongArray>) {
        for (i in 0..3) for (j in 0..15) p[i][j] = q[i][j]
    }

    private fun cswap(p: Array<LongArray>, q: Array<LongArray>, b: Int) {
        for (i in 0..3) sel25519(p[i], q[i], b)
    }

    private fun add(p: Array<LongArray>, q: Array<LongArray>) {
        val a = LongArray(16)
        val b = LongArray(16)
        val c = LongArray(16)
        val d = LongArray(16)
        val e = LongArray(16)
        val f = LongArray(16)
        val g = LongArray(16)
        val h = LongArray(16)
        val t = LongArray(16)

        Z(a, p[1], p[0])
        Z(t, q[1], q[0])
        M(a, a, t)
        A(b, p[0], p[1])
        A(t, q[0], q[1])
        M(b, b, t)
        M(c, p[3], q[3])
        M(c, c, D2)
        M(d, p[2], q[2])
        A(d, d, d)
        Z(e, b, a)
        Z(f, d, c)
        A(g, d, c)
        A(h, b, a)

        M(p[0], e, f)
        M(p[1], h, g)
        M(p[2], g, f)
        M(p[3], e, h)
    }

    private fun pack(r: ByteArray, p: Array<LongArray>) {
        val tx = LongArray(16)
        val ty = LongArray(16)
        val zi = LongArray(16)
        inv25519(zi, p[2])
        M(tx, p[0], zi)
        M(ty, p[1], zi)
        pack25519(r, 0, ty)
        r[31] = (r[31].toInt() xor (par25519(tx) shl 7)).toByte()
    }

    private fun unpackneg(r: Array<LongArray>, p: ByteArray): Boolean {
        val t = LongArray(16)
        val chk = LongArray(16)
        val num = LongArray(16)
        val den = LongArray(16)
        val den2 = LongArray(16)
        val den4 = LongArray(16)
        val den6 = LongArray(16)

        for (i in 0..15) r[2][i] = gf1[i]
        unpack25519(r[1], p)
        S(num, r[1])
        M(den, num, D)
        Z(num, num, r[2])
        A(den, r[2], den)

        S(den2, den)
        S(den4, den2)
        M(den6, den4, den2)
        M(t, den6, num)
        M(t, t, den)

        pow2523(t, t)
        M(t, t, num)
        M(t, t, den)
        M(t, t, den)
        M(r[0], t, den)

        S(chk, r[0])
        M(chk, chk, den)
        if (neq25519(chk, num)) M(r[0], r[0], I)

        S(chk, r[0])
        M(chk, chk, den)
        if (neq25519(chk, num)) return false

        if (par25519(r[0]) == (p[31].toInt() ushr 7) and 1) Z(r[0], gf0, r[0])

        M(r[3], r[0], r[1])
        return true
    }

    private fun scalarbase(p: Array<LongArray>, s: ByteArray) {
        val q = newPoint()
        for (i in 0..15) q[0][i] = X[i]
        for (i in 0..15) q[1][i] = Y[i]
        for (i in 0..15) q[2][i] = gf1[i]
        M(q[3], X, Y)
        scalarmult(p, q, s)
    }

    private fun scalarmult(p: Array<LongArray>, q: Array<LongArray>, s: ByteArray) {
        for (i in 0..15) {
            p[0][i] = gf0[i]
            p[1][i] = gf1[i]
            p[2][i] = gf1[i]
            p[3][i] = gf0[i]
        }
        for (i in 255 downTo 0) {
            val b = (s[i / 8].toInt() ushr (i and 7)) and 1
            cswap(p, q, b)
            add(q, p)
            add(p, p)
            cswap(p, q, b)
        }
    }

    private fun modL(r: ByteArray, rOff: Int, x: LongArray) {
        var carry: Long
        for (i in 63 downTo 32) {
            carry = 0
            var j = i - 32
            val k = i - 12
            while (j < k) {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)]
                carry = (x[j] + 128) shr 8
                x[j] -= carry shl 8
                j++
            }
            x[j] += carry
            x[i] = 0
        }
        carry = 0
        for (j in 0..31) {
            x[j] += carry - (x[31] shr 4) * L[j]
            carry = x[j] shr 8
            x[j] = x[j] and 255
        }
        for (j in 0..31) x[j] -= carry * L[j]
        for (i in 0..31) {
            x[i + 1] += x[i] shr 8
            r[rOff + i] = (x[i] and 255).toByte()
        }
    }

    private fun reduce(r: ByteArray) {
        val x = LongArray(64)
        for (i in 0..63) x[i] = r[i].toLong() and 0xff
        for (i in 0..63) r[i] = 0
        modL(r, 0, x)
    }

    // ===== Public API =====

    fun generatePublicKey(seed: ByteArray): ByteArray {
        val pk = ByteArray(32)
        val hash = sha512(seed)
        hash[0] = (hash[0].toInt() and 248).toByte()
        hash[31] = (hash[31].toInt() and 127 or 64).toByte()

        val p = newPoint()
        scalarbase(p, hash)
        pack(pk, p)
        return pk
    }

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        val hash = sha512(seed)
        hash[0] = (hash[0].toInt() and 248).toByte()
        hash[31] = (hash[31].toInt() and 127 or 64).toByte()

        val publicKey = ByteArray(32)
        val p = newPoint()
        scalarbase(p, hash)
        pack(publicKey, p)

        // r = SHA-512(hash[32..63] || message)
        val prefix = hash.copyOfRange(32, 64)
        val rHash = sha512(prefix + message)
        reduce(rHash)

        // R = r * B
        val rPoint = newPoint()
        scalarbase(rPoint, rHash)
        val signature = ByteArray(64)
        pack(signature, rPoint)

        // k = SHA-512(R || publicKey || message)
        val kHash = sha512(signature.copyOf(32) + publicKey + message)
        reduce(kHash)

        // s = (r + k * a) mod L
        val x = LongArray(64)
        for (i in 0..31) x[i] = rHash[i].toLong() and 0xff
        for (i in 0..31) for (j in 0..31) {
            x[i + j] += (kHash[i].toLong() and 0xff) * (hash[j].toLong() and 0xff)
        }
        modL(signature, 32, x)

        return signature
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != 64) return false
        if (publicKey.size != 32) return false

        val q = newPoint()
        if (!unpackneg(q, publicKey)) return false

        // k = SHA-512(R || publicKey || message)
        val kHash = sha512(signature.copyOf(32) + publicKey + message)
        reduce(kHash)

        // Check: [s]B + [k](-A) == R
        val s = signature.copyOfRange(32, 64)
        val p = newPoint()
        scalarmult(p, q, kHash)

        val sPoint = newPoint()
        scalarbase(sPoint, s)
        add(p, sPoint)

        val t = ByteArray(32)
        pack(t, p)

        return t.contentEquals(signature.copyOf(32))
    }
}
