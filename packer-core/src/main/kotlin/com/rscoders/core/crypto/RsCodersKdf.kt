package com.rscoders.core.crypto

object RsCodersKdf {

    val K0 = intArrayOf(
        0x91460843.toInt(), 0xcabae939.toInt(), 0xc5e28c38.toInt(), 0x7a2fdc28,
        0x18a2e2a1, 0x21784ca6, 0x15db9d78, 0x4eb32c64
    )
    val K1 = intArrayOf(
        0xad92c462.toInt(), 0x72954880, 0x879731e3.toInt(), 0x0105ee9e,
        0x866a7a1b.toInt(), 0xcc15a0fb.toInt(), 0xc4c8817d.toInt(), 0xcde39778.toInt()
    )

    private fun Int.rl(n: Int): Int = (this shl n) or (this ushr (32 - n))
    private fun Int.rr(n: Int): Int = (this ushr n) or (this shl (32 - n))
    private fun Int.u(): Long = this.toLong() and 0xFFFFFFFFL

    private fun roHi(ah: Int, al: Int, n: Int): Pair<Int, Int> {
        if (n == 0) return ah to al
        if (n == 32) return al to ah
        return if (n < 32)
            ((ah shl n) or (al ushr (32 - n))) to ((al shl n) or (ah ushr (32 - n)))
        else {
            val m = n - 32
            ((al shl m) or (ah ushr (32 - m))) to ((ah shl m) or (al ushr (32 - m)))
        }
    }

    private fun addHi(ah: Int, al: Int, bh: Int, bl: Int): Pair<Int, Int> {
        val lo = al.u() + bl.u()
        val carry = if ((lo and 0xFFFFFFFFL) < al.u()) 1L else 0L
        return (ah.u() + bh.u() + carry).toInt() to lo.toInt()
    }

    private fun sipRound(v: IntArray): IntArray {
        var v0h=v[0]; var v0l=v[1]; var v1h=v[2]; var v1l=v[3]
        var v2h=v[4]; var v2l=v[5]; var v3h=v[6]; var v3l=v[7]
        var r: Pair<Int,Int>
        r=addHi(v0h,v0l,v1h,v1l); v0h=r.first; v0l=r.second
        r=roHi(v1h,v1l,13);        v1h=r.first; v1l=r.second
        v1h=v1h xor v0h; v1l=v1l xor v0l
        r=roHi(v0h,v0l,32);        v0h=r.first; v0l=r.second
        r=addHi(v2h,v2l,v3h,v3l); v2h=r.first; v2l=r.second
        r=roHi(v3h,v3l,16);        v3h=r.first; v3l=r.second
        v3h=v3h xor v2h; v3l=v3l xor v2l
        r=addHi(v0h,v0l,v3h,v3l); v0h=r.first; v0l=r.second
        r=roHi(v3h,v3l,21);        v3h=r.first; v3l=r.second
        v3h=v3h xor v0h; v3l=v3l xor v0l
        r=addHi(v2h,v2l,v1h,v1l); v2h=r.first; v2l=r.second
        r=roHi(v1h,v1l,17);        v1h=r.first; v1l=r.second
        v1h=v1h xor v2h; v1l=v1l xor v2l
        r=roHi(v2h,v2l,32);        v2h=r.first; v2l=r.second
        return intArrayOf(v0h,v0l,v1h,v1l,v2h,v2l,v3h,v3l)
    }

    fun siphashTag(input: ByteArray): String {
        val kh0 = K0[0] xor K0[4]; val kl0 = K0[1] xor K0[5]
        val kh1 = K0[2] xor K0[6]; val kl1 = K0[3] xor K0[7]
        var v = intArrayOf(
            kh0 xor 0x736f6d65.toInt(), kl0 xor 0x70736575.toInt(),
            kh1 xor 0x6e646f6d.toInt(), kl1 xor 0x6c796765,
            kh0 xor 0x646f7261.toInt(), kl0 xor 0x6e646f6d.toInt(),
            kh1 xor 0x79746573.toInt(), kl1 xor 0x73697661.toInt()
        )
        val len = input.size; val blen = len and 7.inv()
        var i = 0
        while (i < blen) {
            val ml = (input[i].toInt() and 0xFF) or ((input[i+1].toInt() and 0xFF) shl 8) or
                     ((input[i+2].toInt() and 0xFF) shl 16) or ((input[i+3].toInt() and 0xFF) shl 24)
            val mh = (input[i+4].toInt() and 0xFF) or ((input[i+5].toInt() and 0xFF) shl 8) or
                     ((input[i+6].toInt() and 0xFF) shl 16) or ((input[i+7].toInt() and 0xFF) shl 24)
            v[6]=v[6] xor mh; v[7]=v[7] xor ml
            v=sipRound(sipRound(v))
            v[0]=v[0] xor mh; v[1]=v[1] xor ml
            i += 8
        }
        val last = ByteArray(8)
        last[7] = (len and 0xFF).toByte()
        for (j in 0 until (len and 7)) last[j] = input[blen + j]
        val ml = (last[0].toInt() and 0xFF) or ((last[1].toInt() and 0xFF) shl 8) or
                 ((last[2].toInt() and 0xFF) shl 16) or ((last[3].toInt() and 0xFF) shl 24)
        val mh = (last[4].toInt() and 0xFF) or ((last[5].toInt() and 0xFF) shl 8) or
                 ((last[6].toInt() and 0xFF) shl 16) or ((last[7].toInt() and 0xFF) shl 24)
        v[6]=v[6] xor mh; v[7]=v[7] xor ml
        v=sipRound(sipRound(v))
        v[0]=v[0] xor mh; v[1]=v[1] xor ml
        v[4]=v[4] xor 0xFF
        repeat(4) { v=sipRound(v) }
        val fh = (v[0] xor v[2] xor v[4] xor v[6]).u()
        val fl = (v[1] xor v[3] xor v[5] xor v[7]).u()
        return fh.toString(16).padStart(8,'0') + fl.toString(16).padStart(8,'0')
    }

    private fun speckRound(x: Int, y: Int, k: Int): Pair<Int, Int> {
        var nx = x.rr(8)
        nx = (nx.u() + y.u()).toInt()
        nx = nx xor k
        val ny = y.rl(3) xor nx
        return nx to ny
    }

    fun speckEnc(hexStr: String): String {
        val k0=K0[0] xor K1[0]; val k1=K0[1] xor K1[1]
        val k2=K0[2] xor K1[2]; val k3=K0[3] xor K1[3]
        val sched = mutableListOf<Int>()
        var a=k0; var b=k1; var c=k2; var d=k3
        sched.add(a)
        for (idx in 0 until 27) {
            var r=speckRound(b,a,idx); b=r.first; a=r.second; sched.add(a)
            if (idx % 3 == 0 && idx > 0) {
                r=speckRound(c,a,idx);   c=r.first; a=r.second; sched.add(a)
                r=speckRound(d,a,idx+1); d=r.first; a=r.second; sched.add(a)
            }
        }
        val ks = sched.take(27)
        val w = mutableListOf<Int>()
        for (i in 0 until 16 step 2) w.add(hexStr.substring(i*2, i*2+8).toLong(16).toInt())
        var x = w.getOrElse(0){0}; var y = w.getOrElse(1){0}
        for (k in ks) { val r=speckRound(x,y,k); x=r.first; y=r.second }
        return x.u().toString(16).padStart(8,'0') + y.u().toString(16).padStart(8,'0')
    }

    fun chacha20Enc(hexStr: String): String {
        fun qr(s: IntArray, a: Int, b: Int, c: Int, dd: Int, n: Int) {
            s[a]=(s[a]+s[b]); s[dd]=s[dd] xor s[a]; s[dd]=s[dd].rl(n)
            s[c]=(s[c]+s[dd]); s[b]=s[b] xor s[c]; s[b]=s[b].rl(32-n)
        }
        val key = IntArray(8) { K0[it] xor K1[it] }
        val nA = K0[0] xor K1[4]; val nB = K0[1] xor K1[5]
        val C = intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
        val s = intArrayOf(C[0],C[1],C[2],C[3],key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7],0,0,nA,nB)
        val w = s.copyOf()
        repeat(10) {
            qr(w,0,4,8,12,16);  qr(w,1,5,9,13,12)
            qr(w,2,6,10,14,8);  qr(w,3,7,11,15,7)
            qr(w,0,5,10,15,16); qr(w,1,6,11,12,12)
            qr(w,2,7,8,13,8);   qr(w,3,4,9,14,7)
        }
        for (i in 0 until 16) w[i]=(w[i]+s[i])
        val bytes = hexStr.chunked(2).map { it.toInt(16) }
        val sb = StringBuilder()
        for (i in bytes.indices) {
            val kb = (w[i ushr 2] ushr ((i and 3)*8)) and 0xFF
            sb.append((bytes[i] xor kb).toString(16).padStart(2,'0'))
        }
        return sb.toString()
    }

    fun poly1305Tag(str: String, keyHex: String): String {
        val P  = java.math.BigInteger("3fffffffffffffffffffffffffffffffb", 16)
        val M  = java.math.BigInteger("ffffffffffffffffffffffffffffffff", 16)
        val CL = java.math.BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16)
        val kBytes = keyHex.padEnd(64,'0').substring(0,64).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        fun lu(buf: ByteArray, off: Int, n: Int): java.math.BigInteger {
            var v = java.math.BigInteger.ZERO
            for (j in 0 until n) if (off+j < buf.size)
                v = v.or(java.math.BigInteger.valueOf((buf[off+j].toInt() and 0xFF).toLong()).shiftLeft(j*8))
            return v
        }
        val r = lu(kBytes,0,16).and(CL)
        val s = lu(kBytes,16,16)
        val bytes = str.toByteArray(Charsets.UTF_8)
        var acc = java.math.BigInteger.ZERO
        var i = 0
        while (i < bytes.size) {
            val end = minOf(i+16, bytes.size)
            var chunk = lu(bytes,i,end-i)
            chunk = chunk.or(java.math.BigInteger.ONE.shiftLeft((end-i)*8))
            acc = acc.add(chunk).multiply(r).mod(P)
            i += 16
        }
        acc = acc.add(s).and(M)
        val sb = StringBuilder()
        var tmp = acc
        repeat(16) {
            sb.append((tmp.and(java.math.BigInteger.valueOf(0xFF)).toInt()).toString(16).padStart(2,'0'))
            tmp = tmp.shiftRight(8)
        }
        return sb.toString()
    }

    private fun mul32(a: Int, b: Int): Int {
        val ah = (a ushr 16) and 0xFFFF; val al = a and 0xFFFF
        val bh = (b ushr 16) and 0xFFFF; val bl = b and 0xFFFF
        return (al*bl + (((ah*bl + al*bh) shl 16))).toInt()
    }

    private fun rcMix(a: Int, b: Int, c: Int): Triple<Int,Int,Int> {
        var na = mul32(a xor b, 0x9e3779b9.toInt())
        var nb = mul32(b xor c, 0x85ebca6b.toInt())
        var nc = mul32(c xor na, 0xc2b2ae35.toInt())
        na = (na xor nb.rr(13) xor nc.rl(7))
        nb = (nb xor nc.rr(17) xor na.rl(11))
        nc = (nc xor na.rr(5)  xor nb.rl(19))
        return Triple(na,nb,nc)
    }

    fun customRcEnc(hexStr: String): String {
        val k0=K0[0] xor K1[2]; val k1=K0[3] xor K1[1]
        val k2=K0[5] xor K1[7]; val k3=K0[6] xor K1[4]
        val s = intArrayOf(k0,k1,k2,k3,k0 xor k2,k1 xor k3,k0 xor k1 xor 0xdeadbeef.toInt(),k2 xor k3 xor 0xcafebabe.toInt())
        val sched = mutableListOf<Int>()
        for (i in 0 until 24) {
            val t=rcMix(s[i%8],s[(i+3)%8],s[(i+5)%8])
            s[i%8]=t.first; s[(i+3)%8]=t.second; s[(i+5)%8]=t.third
            if (i%3==0) sched.add(s[(i+1)%8])
        }
        val state = intArrayOf(K0[1] xor K1[3],K0[4] xor K1[6],K0[7] xor K1[0],K0[2] xor K1[5])
        val bytes = hexStr.chunked(2).map { it.toInt(16) }
        val sb = StringBuilder()
        for (i in bytes.indices) {
            val si=i%4; val ki=i%sched.size
            val t=rcMix(state[si],sched[ki],state[(si+2)%4])
            state[si]=t.first; state[(si+1)%4]=t.second
            if (t.third and 1 != 0) { val tmp=state[(si+2)%4]; state[(si+2)%4]=state[(si+3)%4]; state[(si+3)%4]=tmp }
            val kb = (t.first xor t.second xor t.third) and 0xFF
            sb.append((bytes[i] xor kb).toString(16).padStart(2,'0'))
        }
        return sb.toString()
    }

    private val GIMLI_RC = intArrayOf(
        0x9e377904.toInt(),0x9e377908.toInt(),0x9e37790c.toInt(),0x9e377910.toInt(),
        0x9e377914.toInt(),0x9e377918.toInt(),0x9e37791c.toInt(),0x9e377920.toInt(),
        0x9e377924.toInt(),0x9e377928.toInt(),0x9e37792c.toInt(),0x9e377930.toInt(),
        0x9e377934.toInt(),0x9e377938.toInt(),0x9e37793c.toInt(),0x9e377940.toInt(),
        0x9e377944.toInt(),0x9e377948.toInt(),0x9e37794c.toInt(),0x9e377950.toInt(),
        0x9e377954.toInt(),0x9e377958.toInt(),0x9e37795c.toInt(),0x9e377960.toInt()
    )

    private fun gimliPerm(s: IntArray): IntArray {
        for (i in 23 downTo 0) {
            for (col in 0 until 4) {
                val x=s[col].rl(24); val y=s[4+col].rl(9); val z=s[8+col]
                s[8+col]=(x xor (z shl 1) xor ((y and z) shl 2))
                s[4+col]=(y xor x xor ((x or z) shl 1))
                s[col]  =(z xor y xor ((x and y) shl 3))
            }
            if ((i and 3)==0) {
                var t=s[0]; s[0]=s[1]; s[1]=t; t=s[2]; s[2]=s[3]; s[3]=t
                s[0]=s[0] xor GIMLI_RC[i]
            } else if ((i and 3)==2) {
                var t=s[0]; s[0]=s[2]; s[2]=t; t=s[1]; s[1]=s[3]; s[3]=t
            }
        }
        return s
    }

    fun gimliEnc(hexStr: String): String {
        val s = intArrayOf(
            K0[0] xor K1[3],K0[2] xor K1[5],K0[4] xor K1[7],K0[6] xor K1[1],
            K0[1] xor K1[4],K0[3] xor K1[6],K0[5] xor K1[0],K0[7] xor K1[2],
            K0[0] xor K1[0],K0[1] xor K1[1],K0[2] xor K1[2],K0[3] xor K1[3]
        )
        gimliPerm(s)
        val bytes = hexStr.chunked(2).map { it.toInt(16) }
        val ks = mutableListOf<Int>()
        for (i in 0 until 4) { val w=s[i]; for (b in 0 until 4) ks.add((w ushr (b*8)) and 0xFF) }
        var pos = 0; val sb = StringBuilder()
        for (i in bytes.indices) {
            if (pos >= ks.size) {
                gimliPerm(s); ks.clear()
                for (j in 0 until 4) { val w=s[j]; for (b in 0 until 4) ks.add((w ushr (b*8)) and 0xFF) }
                pos=0
            }
            sb.append((bytes[i] xor ks[pos++]).toString(16).padStart(2,'0'))
        }
        return sb.toString()
    }

    private val XOODOO_RC = intArrayOf(
        0x00000058,0x00000038,0x000003C0,0x000000D0,
        0x00000120,0x00000014,0x00000060,0x0000002C,
        0x00000380,0x000000F0,0x000001A0,0x00000012
    )

    private fun xoodooPerm(s: IntArray): IntArray {
        for (i in 0 until 12) {
            val p0=(s[0] xor s[4] xor s[8]).let { it.rl(5) xor it.rl(14) }
            val p1=(s[1] xor s[5] xor s[9]).let { it.rl(5) xor it.rl(14) }
            val p2=(s[2] xor s[6] xor s[10]).let { it.rl(5) xor it.rl(14) }
            val p3=(s[3] xor s[7] xor s[11]).let { it.rl(5) xor it.rl(14) }
            val a0=s[0] xor p0; val a4=s[4] xor p0; val a8=s[8]  xor p0
            val b1=s[1] xor p1; val b5=s[5] xor p1; val b9=s[9]  xor p1
            val c2=s[2] xor p2; val c6=s[6] xor p2; val c10=s[10] xor p2
            val d3=s[3] xor p3; val d7=s[7] xor p3; val d11=s[11] xor p3
            val e0=a0.rl(11); val e1=b1.rl(11); val e2=c2.rl(11); val e3=d3.rl(11)
            s[0]=(e0 xor a4 xor (a4 and a8));  s[4]=(a8 xor e1 xor (a0 and a8));  s[8]=(a0 xor e1 xor (a0 and a4))
            s[1]=(e1 xor b5 xor (b5 and b9));  s[5]=(b9 xor e2 xor (b1 and b9));  s[9]=(b1 xor e2 xor (b1 and b5))
            s[2]=(e2 xor c6 xor (c6 and c10)); s[6]=(c10 xor e3 xor (c2 and c10)); s[10]=(c2 xor e3 xor (c2 and c6))
            s[3]=(e3 xor d7 xor (d7 and d11)); s[7]=(d11 xor e0 xor (d3 and d11)); s[11]=(d3 xor e0 xor (d3 and d7))
            val tmp=s[7]; s[7]=s[4]; s[4]=s[5]; s[5]=s[6]; s[6]=tmp
            s[8]=s[8].rl(11); s[9]=s[9].rl(11); s[10]=s[10].rl(11); s[11]=s[11].rl(11)
            s[0]=s[0] xor XOODOO_RC[i]
        }
        return s
    }

    fun xoodooTag(hexStr: String): String {
        val s = intArrayOf(
            K0[0] xor K1[1],K0[2] xor K1[3],K0[4] xor K1[5],K0[6] xor K1[7],
            K0[1] xor K1[2],K0[3] xor K1[4],K0[5] xor K1[6],K0[7] xor K1[0],
            0,0,0,0
        )
        xoodooPerm(s)
        val bytes = hexStr.chunked(2).map { it.toInt(16) }
        val bs=16; var i=0
        while (i < bytes.size) {
            val block=bytes.subList(i, minOf(i+bs, bytes.size))
            for (j in block.indices) s[j ushr 2]=s[j ushr 2] xor (block[j] shl ((j and 3)*8))
            if (block.size < bs) s[block.size ushr 2]=s[block.size ushr 2] xor (0x01 shl ((block.size and 3)*8))
            xoodooPerm(s)
            i += bs
        }
        if (bytes.size % bs == 0) { s[4]=s[4] xor 0x01; xoodooPerm(s) }
        val sb=StringBuilder()
        for (k in 0 until 4) sb.append(s[k].u().toString(16).padStart(8,'0'))
        return sb.toString()
    }

    private val BLAKE3_IV = intArrayOf(
        0x6a09e667, 0xbb67ae85.toInt(), 0x3c6ef372.toInt(), 0xa54ff53a.toInt(),
        0x510e527f, 0x9b05688c.toInt(), 0x1f83d9ab, 0x5be0cd19
    )
    private val BLAKE3_MSG_PERM = intArrayOf(2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8)

    private fun blake3G(v: IntArray, a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
        v[a]=(v[a]+v[b]+x); v[d]=(v[d] xor v[a]).rl(16)
        v[c]=(v[c]+v[d]);   v[b]=(v[b] xor v[c]).rl(12)
        v[a]=(v[a]+v[b]+y); v[d]=(v[d] xor v[a]).rl(8)
        v[c]=(v[c]+v[d]);   v[b]=(v[b] xor v[c]).rl(7)
    }

    private fun blake3Compress(cv: IntArray, block: ByteArray, counter: Int, blen: Int, flags: Int): IntArray {
        val m=IntArray(16)
        for (i in 0 until 16) m[i]=(block[i*4].toInt() and 0xFF) or ((block[i*4+1].toInt() and 0xFF) shl 8) or
            ((block[i*4+2].toInt() and 0xFF) shl 16) or ((block[i*4+3].toInt() and 0xFF) shl 24)
        val v=intArrayOf(cv[0],cv[1],cv[2],cv[3],cv[4],cv[5],cv[6],cv[7],
            BLAKE3_IV[0],BLAKE3_IV[1],BLAKE3_IV[2],BLAKE3_IV[3],counter,0,blen,flags)
        var ms=m.copyOf()
        for (i in 0 until 7) {
            blake3G(v,0,4,8,12,ms[0],ms[1]);  blake3G(v,1,5,9,13,ms[2],ms[3])
            blake3G(v,2,6,10,14,ms[4],ms[5]); blake3G(v,3,7,11,15,ms[6],ms[7])
            blake3G(v,0,5,10,15,ms[8],ms[9]); blake3G(v,1,6,11,12,ms[10],ms[11])
            blake3G(v,2,7,8,13,ms[12],ms[13]);blake3G(v,3,4,9,14,ms[14],ms[15])
            if (i < 6) { val nm=IntArray(16); for (p in 0 until 16) nm[p]=ms[BLAKE3_MSG_PERM[p]]; ms=nm }
        }
        return IntArray(8) { v[it] xor v[it+8] }
    }

    fun blake3Enc(hexStr: String): String {
        val key = intArrayOf(
            K0[0] xor K1[4],K0[1] xor K1[5],K0[2] xor K1[6],K0[3] xor K1[7],
            K0[4] xor K1[0],K0[5] xor K1[1],K0[6] xor K1[2],K0[7] xor K1[3]
        )
        val bytes = hexStr.chunked(2).map { it.toInt(16) }
        val sb = StringBuilder(); var ctr=0
        var i=0
        while (i < bytes.size) {
            val block=ByteArray(64)
            val chunk=bytes.subList(i, minOf(i+64, bytes.size))
            for (j in chunk.indices) block[j]=chunk[j].toByte()
            val ks=blake3Compress(key,block,ctr++,chunk.size,0x0b)
            for (j in chunk.indices) {
                val kb=(ks[j ushr 2] ushr ((j and 3)*8)) and 0xFF
                sb.append((chunk[j] xor kb).toString(16).padStart(2,'0'))
            }
            i += 64
        }
        return sb.toString()
    }

    fun chaskeyTag(hexStr: String): String {
        fun perm(s: IntArray): IntArray {
            repeat(12) {
                s[0]=(s[0]+s[1]); s[3]=(s[3] xor s[0]).rl(16)
                s[2]=(s[2]+s[3]); s[1]=(s[1] xor s[2]).rl(12)
                s[0]=(s[0]+s[1]); s[3]=(s[3] xor s[0]).rl(8)
                s[2]=(s[2]+s[3]); s[1]=(s[1] xor s[2]).rl(5)
            }
            return s
        }
        val k0=K0[0] xor K1[6]; val k1=K0[2] xor K1[4]
        val k2=K0[5] xor K1[3]; val k3=K0[7] xor K1[1]
        val k1s = intArrayOf(
            (k0.rl(1) xor k1.rl(1) xor (k0 ushr 31) xor (k1 ushr 31)),
            (k1.rl(1) xor k2.rl(1) xor (k1 ushr 31) xor (k2 ushr 31)),
            (k2.rl(1) xor k3.rl(1) xor (k2 ushr 31) xor (k3 ushr 31)),
            (k3.rl(1) xor k0.rl(1) xor (k3 ushr 31) xor (k0 ushr 31))
        )
        val k2s = intArrayOf(
            (k1s[0].rl(1) xor k1s[1].rl(1) xor (k1s[0] ushr 31) xor (k1s[1] ushr 31)),
            (k1s[1].rl(1) xor k1s[2].rl(1) xor (k1s[1] ushr 31) xor (k1s[2] ushr 31)),
            (k1s[2].rl(1) xor k1s[3].rl(1) xor (k1s[2] ushr 31) xor (k1s[3] ushr 31)),
            (k1s[3].rl(1) xor k1s[0].rl(1) xor (k1s[3] ushr 31) xor (k1s[0] ushr 31))
        )
        val bytes = hexStr.chunked(2).map { it.toInt(16) }
        var s = intArrayOf(k0,k1,k2,k3)
        val bs=16; val len=bytes.size; var i=0
        while (i < len) {
            val isLast=(i+bs)>=len
            val block=IntArray(4)
            val chunk=bytes.subList(i, minOf(i+bs, bytes.size))
            val arr=ByteArray(16)
            for (j in chunk.indices) arr[j]=chunk[j].toByte()
            if (isLast && chunk.size==bs) { s[0]=s[0] xor k1s[0]; s[1]=s[1] xor k1s[1]; s[2]=s[2] xor k1s[2]; s[3]=s[3] xor k1s[3] }
            else if (isLast) { arr[chunk.size]=0x01; s[0]=s[0] xor k2s[0]; s[1]=s[1] xor k2s[1]; s[2]=s[2] xor k2s[2]; s[3]=s[3] xor k2s[3] }
            for (j in 0 until 16 step 4) {
                val w=(arr[j].toInt() and 0xFF) or ((arr[j+1].toInt() and 0xFF) shl 8) or
                      ((arr[j+2].toInt() and 0xFF) shl 16) or ((arr[j+3].toInt() and 0xFF) shl 24)
                s[j ushr 2]=s[j ushr 2] xor w
            }
            s=perm(s)
            i += bs
        }
        s[0]=s[0] xor k1s[0]; s[1]=s[1] xor k1s[1]; s[2]=s[2] xor k1s[2]; s[3]=s[3] xor k1s[3]
        val sb=StringBuilder()
        for (k in 0 until 4) sb.append(s[k].u().toString(16).padStart(8,'0'))
        return sb.toString()
    }

    private fun sha256Block(H: IntArray, W: IntArray) {
        val T = intArrayOf(
            0x428a2f98.toInt(),0x71374491,0xb5c0fbcf.toInt(),0xe9b5dba5.toInt(),0x3956c25b,0x59f111f1,0x923f82a4.toInt(),0xab1c5ed5.toInt(),
            0xd807aa98.toInt(),0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe.toInt(),0x9bdc06a7.toInt(),0xc19bf174.toInt(),
            0xe49b69c1.toInt(),0xefbe4786.toInt(),0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152.toInt(),0xa831c66d.toInt(),0xb00327c8.toInt(),0xbf597fc7.toInt(),0xc6e00bf3.toInt(),0xd5a79147.toInt(),0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e.toInt(),0x92722c85.toInt(),
            0xa2bfe8a1.toInt(),0xa81a664b.toInt(),0xc24b8b70.toInt(),0xc76c51a3.toInt(),0xd192e819.toInt(),0xd6990624.toInt(),0xf40e3585.toInt(),0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814.toInt(),0x8cc70208.toInt(),0x90befffa.toInt(),0xa4506ceb.toInt(),0xbef9a3f7.toInt(),0xc67178f2.toInt()
        )
        for (i in 16 until 64) {
            val s0 = W[i-15].rr(7) xor W[i-15].rr(18) xor (W[i-15] ushr 3)
            val s1 = W[i-2].rr(17) xor W[i-2].rr(19) xor (W[i-2] ushr 10)
            W[i] = (W[i-16]+s0+W[i-7]+s1)
        }
        var a=H[0];var b=H[1];var c=H[2];var d=H[3];var e=H[4];var f=H[5];var g=H[6];var h=H[7]
        for (i in 0 until 64) {
            val t1 = h + (e.rr(6) xor e.rr(11) xor e.rr(25)) + ((e and f) xor (e.inv() and g)) + T[i] + W[i]
            val t2 = (a.rr(2) xor a.rr(13) xor a.rr(22)) + ((a and b) xor (a and c) xor (b and c))
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2
        }
        H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h
    }

    private fun sha256Digest(initH: IntArray, data: ByteArray): String {
        val H = initH.copyOf()
        val len = data.size; val blen = ((len+8)/64+1)*64
        val buf = ByteArray(blen); data.copyInto(buf); buf[len]=0x80.toByte()
        var bits = len.toLong()*8
        for (i in 0 until 8) { buf[blen-1-i]=(bits%256).toInt().toByte(); bits/=256 }
        var i=0
        while (i < blen) {
            val W=IntArray(64)
            for (j in 0 until 16) W[j]=(buf[i+j*4].toInt() shl 24) or ((buf[i+j*4+1].toInt() and 0xFF) shl 16) or
                ((buf[i+j*4+2].toInt() and 0xFF) shl 8) or (buf[i+j*4+3].toInt() and 0xFF)
            sha256Block(H,W)
            i+=64
        }
        return H.joinToString("") { it.u().toString(16).padStart(8,'0') }
    }

    fun hmacMac(msg: String): String {
        val inner = sha256Digest(K0, msg.toByteArray(Charsets.UTF_8))
        return sha256Digest(K1, inner.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
    }

    fun pipeline(input: ByteArray): ByteArray {
        val raw = input.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2,'0') }
        val step1 = siphashTag(input)
        val step2 = speckEnc(step1)
        val step3 = chacha20Enc(step2)
        val kd = K0.joinToString("") { it.u().toString(16).padStart(8,'0') }.let { it.substring(0,32)+it.substring(32,64) }
        val step4 = poly1305Tag(step3, kd)
        val step5 = customRcEnc(step4)
        val step6 = gimliEnc(step5)
        val step7 = xoodooTag(step6)
        val step8 = blake3Enc(step7)
        val step9 = chaskeyTag(step8)
        val step10 = hmacMac(step9)
        return step10.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
        val derived = pipeline(key)
        val ks = expandKeystream(derived, plaintext.size + 4)
        val out = ByteArray(plaintext.size + 4)
        val lenBytes = intArrayOf(
            (plaintext.size ushr 24) and 0xFF,
            (plaintext.size ushr 16) and 0xFF,
            (plaintext.size ushr 8)  and 0xFF,
            plaintext.size and 0xFF
        )
        for (i in 0 until 4) out[i] = (lenBytes[i] xor (ks[i].toInt() and 0xFF)).toByte()
        for (i in plaintext.indices) out[i+4] = (plaintext[i].toInt() xor (ks[i+4].toInt() and 0xFF)).toByte()
        return out
    }

    fun decrypt(key: ByteArray, ciphertext: ByteArray): ByteArray {
        val derived = pipeline(key)
        val ks = expandKeystream(derived, ciphertext.size)
        val lenBytes = IntArray(4) { (ciphertext[it].toInt() xor (ks[it].toInt() and 0xFF)) and 0xFF }
        val len = (lenBytes[0] shl 24) or (lenBytes[1] shl 16) or (lenBytes[2] shl 8) or lenBytes[3]
        require(len >= 0 && len <= ciphertext.size - 4) { "invalid ciphertext" }
        return ByteArray(len) { (ciphertext[it+4].toInt() xor (ks[it+4].toInt() and 0xFF)).toByte() }
    }

    private fun expandKeystream(seed: ByteArray, needed: Int): ByteArray {
        val out = ByteArray(needed)
        var filled = 0; var ctr = 0
        while (filled < needed) {
            val block = seed + byteArrayOf(
                (ctr ushr 24).toByte(),(ctr ushr 16).toByte(),(ctr ushr 8).toByte(),ctr.toByte()
            )
            val chunk = pipeline(block)
            val take = minOf(chunk.size, needed - filled)
            chunk.copyInto(out, filled, 0, take)
            filled += take; ctr++
        }
        return out
    }

    fun newKey(): ByteArray {
        val seed = ByteArray(32)
        java.security.SecureRandom().nextBytes(seed)
        return seed
    }
}
