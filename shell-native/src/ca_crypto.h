#ifndef CA_CRYPTO_H
#define CA_CRYPTO_H
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

namespace ca {

static const uint32_t K0[8] = {
    0x91460843u, 0xcabae939u, 0xc5e28c38u, 0x7a2fdc28u,
    0x18a2e2a1u, 0x21784ca6u, 0x15db9d78u, 0x4eb32c64u
};
static const uint32_t K1[8] = {
    0xad92c462u, 0x72954880u, 0x879731e3u, 0x0105ee9eu,
    0x866a7a1bu, 0xcc15a0fbu, 0xc4c8817du, 0xcde39778u
};

static inline uint32_t rl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
static inline uint32_t rr32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

static inline void ro64(uint32_t ah, uint32_t al, int n, uint32_t *oh, uint32_t *ol) {
    if (n == 0)       { *oh=ah; *ol=al; }
    else if (n == 32) { *oh=al; *ol=ah; }
    else if (n < 32)  { *oh=(ah<<n)|(al>>(32-n)); *ol=(al<<n)|(ah>>(32-n)); }
    else { int m=n-32; *oh=(al<<m)|(ah>>(32-m)); *ol=(ah<<m)|(al>>(32-m)); }
}

static inline void add64(uint32_t ah, uint32_t al, uint32_t bh, uint32_t bl, uint32_t *oh, uint32_t *ol) {
    uint64_t lo = (uint64_t)al + bl;
    uint32_t carry = (lo < (uint64_t)al) ? 1u : 0u;
    *ol = (uint32_t)lo;
    *oh = (uint32_t)((uint64_t)ah + bh + carry);
}

static inline void sip_round(uint32_t v[16]) {
    uint32_t rh, rl;
    add64(v[0],v[1],v[2],v[3],&v[0],&v[1]);
    ro64(v[2],v[3],13,&v[2],&v[3]); v[2]^=v[0]; v[3]^=v[1];
    ro64(v[0],v[1],32,&v[0],&v[1]);
    add64(v[4],v[5],v[6],v[7],&v[4],&v[5]);
    ro64(v[6],v[7],16,&v[6],&v[7]); v[6]^=v[4]; v[7]^=v[5];
    add64(v[0],v[1],v[6],v[7],&v[0],&v[1]);
    ro64(v[6],v[7],21,&v[6],&v[7]); v[6]^=v[0]; v[7]^=v[1];
    add64(v[4],v[5],v[2],v[3],&v[4],&v[5]);
    ro64(v[2],v[3],17,&v[2],&v[3]); v[2]^=v[4]; v[3]^=v[5];
    ro64(v[4],v[5],32,&v[4],&v[5]);
}

static void siphash_tag(const uint8_t *input, size_t len, uint8_t out[8]) {
    uint32_t kh0=K0[0]^K0[4], kl0=K0[1]^K0[5], kh1=K0[2]^K0[6], kl1=K0[3]^K0[7];
    uint32_t v[8] = {
        kh0^0x736f6d65u, kl0^0x70736575u,
        kh1^0x6e646f6du, kl1^0x6c796765u,
        kh0^0x646f7261u, kl0^0x6e646f6du,
        kh1^0x79746573u, kl1^0x73697661u
    };
    size_t blen = len & ~(size_t)7;
    for (size_t i = 0; i < blen; i += 8) {
        uint32_t ml = (uint32_t)input[i] | ((uint32_t)input[i+1]<<8) | ((uint32_t)input[i+2]<<16) | ((uint32_t)input[i+3]<<24);
        uint32_t mh = (uint32_t)input[i+4] | ((uint32_t)input[i+5]<<8) | ((uint32_t)input[i+6]<<16) | ((uint32_t)input[i+7]<<24);
        v[6]^=mh; v[7]^=ml;
        sip_round(v); sip_round(v);
        v[0]^=mh; v[1]^=ml;
    }
    uint8_t last[8] = {0}; last[7] = (uint8_t)((len & 0xFF) << 24 >> 24);
    for (size_t j = 0; j < (len & 7); j++) last[j] = input[blen+j];
    uint32_t ml = (uint32_t)last[0] | ((uint32_t)last[1]<<8) | ((uint32_t)last[2]<<16) | ((uint32_t)last[3]<<24);
    uint32_t mh = (uint32_t)last[4] | ((uint32_t)last[5]<<8) | ((uint32_t)last[6]<<16) | ((uint32_t)last[7]<<24);
    v[6]^=mh; v[7]^=ml;
    sip_round(v); sip_round(v);
    v[0]^=mh; v[1]^=ml;
    v[4]^=0xFF;
    for (int r=0;r<4;r++) sip_round(v);
    uint32_t fh = v[0]^v[2]^v[4]^v[6];
    uint32_t fl = v[1]^v[3]^v[5]^v[7];
    memcpy(out,   &fh, 4);
    memcpy(out+4, &fl, 4);
}

static void speck_enc(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint32_t k0=K0[0]^K1[0], k1=K0[1]^K1[1], k2=K0[2]^K1[2], k3=K0[3]^K1[3];
    uint32_t sched[64]; int sc=0;
    uint32_t a=k0, b=k1, c=k2, d=k3; sched[sc++]=a;
    for (int i=0;i<27;i++) {
        b=rr32(b,8); b=(uint32_t)((uint64_t)b+a); b^=(uint32_t)i;
        a=rl32(a,3); a^=b; sched[sc++]=a;
        if (i%3==0 && i>0) {
            c=rr32(c,8); c=(uint32_t)((uint64_t)c+a); c^=(uint32_t)i;
            a=rl32(a,3); a^=c; sched[sc++]=a;
            d=rr32(d,8); d=(uint32_t)((uint64_t)d+a); d^=(uint32_t)(i+1);
            a=rl32(a,3); a^=d; sched[sc++]=a;
        }
    }
    if (sc > 27) sc=27;
    for (size_t i=0; i<inlen; i++) out[i] = in[i] ^ ((sched[i%sc]>>((i%4)*8))&0xFF);
}

static void chacha20_enc(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint32_t key[8]; for(int i=0;i<8;i++) key[i]=K0[i]^K1[i];
    uint32_t nA=K0[0]^K1[4], nB=K0[1]^K1[5];
    uint32_t C[4]={0x61707865u,0x3320646eu,0x79622d32u,0x6b206574u};
    uint32_t s[16]={C[0],C[1],C[2],C[3],key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7],0,0,nA,nB};
    uint32_t w[16]; memcpy(w,s,64);
#define QR(a,b,c,d,n) s[a]+=s[b];s[d]^=s[a];s[d]=rl32(s[d],n);s[c]+=s[d];s[b]^=s[c];s[b]=rl32(s[b],32-n)
    for(int i=0;i<10;i++){
        QR(0,4,8,12,16);QR(1,5,9,13,12);QR(2,6,10,14,8);QR(3,7,11,15,7);
        QR(0,5,10,15,16);QR(1,6,11,12,12);QR(2,7,8,13,8);QR(3,4,9,14,7);
    }
#undef QR
    for(int i=0;i<16;i++) w[i]+=s[i];
    for(size_t i=0;i<inlen;i++) { uint8_t kb=(w[i>>2]>>((i&3)*8))&0xFF; out[i]=in[i]^kb; }
}

static void poly1305_tag(const uint8_t *msg, size_t msglen, uint8_t out[16]) {
    uint8_t kbytes[32];
    uint32_t kd[8]; for(int i=0;i<8;i++) kd[i]=K0[i];
    memcpy(kbytes, kd, 32);
    __uint128_t P = ((__uint128_t)0x3fffffffffffffffllu << 64) | 0xfffffffffffffffbllu;
    __uint128_t M = ((__uint128_t)0xffffffffffffffffllu << 64) | 0xffffffffffffffffllu;
    __uint128_t CL= ((__uint128_t)0x0ffffffc0ffffffcllu << 64) | 0x0ffffffc0fffffffllu;
    __uint128_t r=0, s=0;
    for(int j=0;j<16;j++) r|=(__uint128_t)kbytes[j]<<(j*8);
    r&=CL;
    for(int j=0;j<16;j++) s|=(__uint128_t)kbytes[16+j]<<(j*8);
    __uint128_t acc=0;
    for(size_t i=0;i<msglen;i+=16){
        size_t end=i+16<msglen?i+16:msglen;
        __uint128_t chunk=0;
        for(size_t j=i;j<end;j++) chunk|=(__uint128_t)msg[j]<<((j-i)*8);
        chunk|=(__uint128_t)1<<((end-i)*8);
        acc=(acc+chunk)*r%P;
    }
    acc=(acc+s)&M;
    for(int j=0;j<16;j++) { out[j]=(uint8_t)(acc&0xFF); acc>>=8; }
}

static uint32_t rc_mul32(uint32_t a, uint32_t b) {
    uint32_t ah=(a>>16)&0xFFFF, al=a&0xFFFF, bh=(b>>16)&0xFFFF, bl=b&0xFFFF;
    return al*bl + ((ah*bl+al*bh)<<16);
}

static void rc_mix(uint32_t a, uint32_t b, uint32_t c, uint32_t *ra, uint32_t *rb, uint32_t *rc_) {
    a=rc_mul32(a^b,0x9e3779b9u); b=rc_mul32(b^c,0x85ebca6bu); c=rc_mul32(c^a,0xc2b2ae35u);
    a=(a^rr32(b,13)^rl32(c,7)); b=(b^rr32(c,17)^rl32(a,11)); c=(c^rr32(a,5)^rl32(b,19));
    *ra=a; *rb=b; *rc_=c;
}

static void custom_rc_enc(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint32_t k0=K0[0]^K1[2], k1=K0[3]^K1[1], k2=K0[5]^K1[7], k3=K0[6]^K1[4];
    uint32_t s[8]={k0,k1,k2,k3,k0^k2,k1^k3,k0^k1^0xdeadbeefu,k2^k3^0xcafebabeu};
    uint32_t sched[16]; int sc=0;
    for(int i=0;i<24;i++){
        uint32_t ra,rb,rc_; rc_mix(s[i%8],s[(i+3)%8],s[(i+5)%8],&ra,&rb,&rc_);
        s[i%8]=ra; s[(i+3)%8]=rb; s[(i+5)%8]=rc_;
        if(i%3==0 && sc<16) sched[sc++]=s[(i+1)%8];
    }
    uint32_t state[4]={K0[1]^K1[3],K0[4]^K1[6],K0[7]^K1[0],K0[2]^K1[5]};
    for(size_t i=0;i<inlen;i++){
        int si=i%4, ki=i%sc;
        uint32_t ra,rb,rc_; rc_mix(state[si],sched[ki],state[(si+2)%4],&ra,&rb,&rc_);
        state[si]=ra; state[(si+1)%4]=rb;
        if(rc_&1){ uint32_t t=state[(si+2)%4]; state[(si+2)%4]=state[(si+3)%4]; state[(si+3)%4]=t; }
        uint8_t kb=(ra^rb^rc_)&0xFF; out[i]=in[i]^kb;
    }
}

static const uint32_t GIMLI_RC[24] = {
    0x9e377904u,0x9e377908u,0x9e37790cu,0x9e377910u,0x9e377914u,0x9e377918u,
    0x9e37791cu,0x9e377920u,0x9e377924u,0x9e377928u,0x9e37792cu,0x9e377930u,
    0x9e377934u,0x9e377938u,0x9e37793cu,0x9e377940u,0x9e377944u,0x9e377948u,
    0x9e37794cu,0x9e377950u,0x9e377954u,0x9e377958u,0x9e37795cu,0x9e377960u
};

static void gimli_perm(uint32_t s[12]) {
    for(int i=23;i>=0;i--){
        for(int col=0;col<4;col++){
            uint32_t x=rl32(s[col],24), y=rl32(s[4+col],9), z=s[8+col];
            s[8+col]=x^(z<<1)^((y&z)<<2);
            s[4+col]=y^x^((x|z)<<1);
            s[col]  =z^y^((x&y)<<3);
        }
        if((i&3)==0){ uint32_t t=s[0];s[0]=s[1];s[1]=t; t=s[2];s[2]=s[3];s[3]=t; s[0]^=GIMLI_RC[i]; }
        else if((i&3)==2){ uint32_t t=s[0];s[0]=s[2];s[2]=t; t=s[1];s[1]=s[3];s[3]=t; }
    }
}

static void gimli_enc(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint32_t s[12]={
        K0[0]^K1[3],K0[2]^K1[5],K0[4]^K1[7],K0[6]^K1[1],
        K0[1]^K1[4],K0[3]^K1[6],K0[5]^K1[0],K0[7]^K1[2],
        K0[0]^K1[0],K0[1]^K1[1],K0[2]^K1[2],K0[3]^K1[3]
    };
    gimli_perm(s);
    uint8_t ks[16]; int pos=0;
    for(int i=0;i<4;i++){ memcpy(ks+i*4,&s[i],4); }
    for(size_t i=0;i<inlen;i++){
        if(pos>=16){ gimli_perm(s); for(int j=0;j<4;j++) memcpy(ks+j*4,&s[j],4); pos=0; }
        out[i]=in[i]^ks[pos++];
    }
}

static const uint32_t XOODOO_RC[12]={0x58u,0x38u,0x3C0u,0xD0u,0x120u,0x14u,0x60u,0x2Cu,0x380u,0xF0u,0x1A0u,0x12u};

static void xoodoo_perm(uint32_t s[12]) {
    for(int i=0;i<12;i++){
        uint32_t p0=rl32(s[0]^s[4]^s[8],5)^rl32(s[0]^s[4]^s[8],14);
        uint32_t p1=rl32(s[1]^s[5]^s[9],5)^rl32(s[1]^s[5]^s[9],14);
        uint32_t p2=rl32(s[2]^s[6]^s[10],5)^rl32(s[2]^s[6]^s[10],14);
        uint32_t p3=rl32(s[3]^s[7]^s[11],5)^rl32(s[3]^s[7]^s[11],14);
        uint32_t a0=s[0]^p0,a4=s[4]^p0,a8=s[8]^p0;
        uint32_t b1=s[1]^p1,b5=s[5]^p1,b9=s[9]^p1;
        uint32_t c2=s[2]^p2,c6=s[6]^p2,c10=s[10]^p2;
        uint32_t d3=s[3]^p3,d7=s[7]^p3,d11=s[11]^p3;
        uint32_t e0=rl32(a0,11),e1=rl32(b1,11),e2=rl32(c2,11),e3=rl32(d3,11);
        s[0]=e0^a4^(a4&a8); s[4]=a8^e1^(a0&a8); s[8]=a0^e1^(a0&a4);
        s[1]=e1^b5^(b5&b9); s[5]=b9^e2^(b1&b9); s[9]=b1^e2^(b1&b5);
        s[2]=e2^c6^(c6&c10);s[6]=c10^e3^(c2&c10);s[10]=c2^e3^(c2&c6);
        s[3]=e3^d7^(d7&d11);s[7]=d11^e0^(d3&d11);s[11]=d3^e0^(d3&d7);
        uint32_t tmp=s[7];s[7]=s[4];s[4]=s[5];s[5]=s[6];s[6]=tmp;
        s[8]=rl32(s[8],11);s[9]=rl32(s[9],11);s[10]=rl32(s[10],11);s[11]=rl32(s[11],11);
        s[0]^=XOODOO_RC[i];
    }
}

static void xoodoo_tag(const uint8_t *in, size_t inlen, uint8_t out[16]) {
    uint32_t s[12]={
        K0[0]^K1[1],K0[2]^K1[3],K0[4]^K1[5],K0[6]^K1[7],
        K0[1]^K1[2],K0[3]^K1[4],K0[5]^K1[6],K0[7]^K1[0],
        0,0,0,0
    };
    xoodoo_perm(s);
    for(size_t i=0;i<inlen;i+=16){
        size_t end=i+16<inlen?i+16:inlen;
        for(size_t j=i;j<end;j++) s[(j-i)>>2]^=(uint32_t)in[j]<<(((j-i)&3)*8);
        if((end-i)<16) s[(end-i)>>2]^=(uint32_t)1<<(((end-i)&3)*8);
        xoodoo_perm(s);
    }
    if(inlen%16==0){ s[4]^=0x01; xoodoo_perm(s); }
    memcpy(out, s, 16);
}

static const uint32_t BLAKE3_IV[8]={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
static const int BLAKE3_MSG_PERM[16]={2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};

static void b3G(uint32_t v[16],int a,int b,int c,int d,uint32_t x,uint32_t y){
    v[a]+=v[b]+x; v[d]=rl32(v[d]^v[a],16);
    v[c]+=v[d];   v[b]=rl32(v[b]^v[c],12);
    v[a]+=v[b]+y; v[d]=rl32(v[d]^v[a],8);
    v[c]+=v[d];   v[b]=rl32(v[b]^v[c],7);
}

static void blake3_compress(const uint32_t cv[8], const uint8_t block[64], uint32_t ctr, uint32_t blen, uint32_t flags, uint32_t out[8]) {
    uint32_t m[16];
    for(int i=0;i<16;i++) m[i]=(uint32_t)block[i*4]|((uint32_t)block[i*4+1]<<8)|((uint32_t)block[i*4+2]<<16)|((uint32_t)block[i*4+3]<<24);
    uint32_t v[16]={cv[0],cv[1],cv[2],cv[3],cv[4],cv[5],cv[6],cv[7],BLAKE3_IV[0],BLAKE3_IV[1],BLAKE3_IV[2],BLAKE3_IV[3],ctr,0,blen,flags};
    uint32_t ms[16]; memcpy(ms,m,64);
    for(int i=0;i<7;i++){
        b3G(v,0,4,8,12,ms[0],ms[1]);  b3G(v,1,5,9,13,ms[2],ms[3]);
        b3G(v,2,6,10,14,ms[4],ms[5]); b3G(v,3,7,11,15,ms[6],ms[7]);
        b3G(v,0,5,10,15,ms[8],ms[9]); b3G(v,1,6,11,12,ms[10],ms[11]);
        b3G(v,2,7,8,13,ms[12],ms[13]);b3G(v,3,4,9,14,ms[14],ms[15]);
        if(i<6){ uint32_t nm[16]; for(int p=0;p<16;p++) nm[p]=ms[BLAKE3_MSG_PERM[p]]; memcpy(ms,nm,64); }
    }
    for(int i=0;i<8;i++) out[i]=v[i]^v[i+8];
}

static void blake3_enc(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint32_t key[8]={K0[0]^K1[4],K0[1]^K1[5],K0[2]^K1[6],K0[3]^K1[7],K0[4]^K1[0],K0[5]^K1[1],K0[6]^K1[2],K0[7]^K1[3]};
    uint32_t ctr=0;
    for(size_t i=0;i<inlen;i+=64){
        uint8_t block[64]={0};
        size_t chunk=inlen-i<64?inlen-i:64;
        memcpy(block,in+i,chunk);
        uint32_t ks[8]; blake3_compress(key,block,ctr++,(uint32_t)chunk,0x0bu,ks);
        for(size_t j=0;j<chunk;j++) { uint8_t kb=(ks[j>>2]>>((j&3)*8))&0xFF; out[i+j]=in[i+j]^kb; }
    }
}

static void chaskey_tag(const uint8_t *in, size_t inlen, uint8_t out[16]) {
    uint32_t k0=K0[0]^K1[6],k1=K0[2]^K1[4],k2=K0[5]^K1[3],k3=K0[7]^K1[1];
    uint32_t k1s[4]={rl32(k0,1)^rl32(k1,1)^(k0>>31)^(k1>>31),rl32(k1,1)^rl32(k2,1)^(k1>>31)^(k2>>31),rl32(k2,1)^rl32(k3,1)^(k2>>31)^(k3>>31),rl32(k3,1)^rl32(k0,1)^(k3>>31)^(k0>>31)};
    uint32_t k2s[4]={rl32(k1s[0],1)^rl32(k1s[1],1)^(k1s[0]>>31)^(k1s[1]>>31),rl32(k1s[1],1)^rl32(k1s[2],1)^(k1s[1]>>31)^(k1s[2]>>31),rl32(k1s[2],1)^rl32(k1s[3],1)^(k1s[2]>>31)^(k1s[3]>>31),rl32(k1s[3],1)^rl32(k1s[0],1)^(k1s[3]>>31)^(k1s[0]>>31)};
    uint32_t s[4]={k0,k1,k2,k3};
    for(size_t i=0;i<(inlen==0?1:inlen);i+=16){
        int isLast=(i+16)>=inlen;
        uint8_t block[16]={0};
        size_t chunk=inlen-i<16?inlen-i:16;
        memcpy(block,in+i,chunk);
        if(isLast&&chunk==16){ s[0]^=k1s[0];s[1]^=k1s[1];s[2]^=k1s[2];s[3]^=k1s[3]; }
        else if(isLast){ block[chunk]=0x01; s[0]^=k2s[0];s[1]^=k2s[1];s[2]^=k2s[2];s[3]^=k2s[3]; }
        for(int j=0;j<4;j++){ uint32_t w=(uint32_t)block[j*4]|((uint32_t)block[j*4+1]<<8)|((uint32_t)block[j*4+2]<<16)|((uint32_t)block[j*4+3]<<24); s[j]^=w; }
        for(int r=0;r<12;r++){
            s[0]+=s[1]; s[3]=rl32(s[3]^s[0],16);
            s[2]+=s[3]; s[1]=rl32(s[1]^s[2],12);
            s[0]+=s[1]; s[3]=rl32(s[3]^s[0],8);
            s[2]+=s[3]; s[1]=rl32(s[1]^s[2],5);
        }
        if((size_t)(i+16)>=inlen) break;
    }
    s[0]^=k1s[0];s[1]^=k1s[1];s[2]^=k1s[2];s[3]^=k1s[3];
    memcpy(out,s,16);
}

static const uint32_t SHA256_T[64]={
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_block(uint32_t H[8], uint32_t W[64]) {
    for(int i=16;i<64;i++){
        uint32_t s0=rr32(W[i-15],7)^rr32(W[i-15],18)^(W[i-15]>>3);
        uint32_t s1=rr32(W[i-2],17)^rr32(W[i-2],19)^(W[i-2]>>10);
        W[i]=W[i-16]+s0+W[i-7]+s1;
    }
    uint32_t a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(int i=0;i<64;i++){
        uint32_t t1=h+(rr32(e,6)^rr32(e,11)^rr32(e,25))+((e&f)^(~e&g))+SHA256_T[i]+W[i];
        uint32_t t2=(rr32(a,2)^rr32(a,13)^rr32(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
}

static void sha256_digest(const uint32_t initH[8], const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t H[8]; memcpy(H,initH,32);
    size_t blen=((len+8)/64+1)*64;
    uint8_t *buf=(uint8_t*)calloc(1,blen);
    memcpy(buf,data,len); buf[len]=0x80;
    uint64_t bits=(uint64_t)len*8;
    for(int i=0;i<8;i++) buf[blen-1-i]=(uint8_t)(bits>>(i*8));
    for(size_t i=0;i<blen;i+=64){
        uint32_t W[64];
        for(int j=0;j<16;j++) W[j]=((uint32_t)buf[i+j*4]<<24)|((uint32_t)buf[i+j*4+1]<<16)|((uint32_t)buf[i+j*4+2]<<8)|(uint32_t)buf[i+j*4+3];
        sha256_block(H,W);
    }
    free(buf);
    for(int i=0;i<8;i++){ out[i*4]=(uint8_t)(H[i]>>24);out[i*4+1]=(uint8_t)(H[i]>>16);out[i*4+2]=(uint8_t)(H[i]>>8);out[i*4+3]=(uint8_t)H[i]; }
}

static void hmac_mac(const char *msg, size_t msglen, uint8_t out[32]) {
    uint8_t inner[32]; sha256_digest(K0, (const uint8_t*)msg, msglen, inner);
    sha256_digest(K1, inner, 32, out);
}

static void rs_pipeline(const uint8_t *input, size_t inlen, uint8_t out[32]) {
    uint8_t sip[8];       siphash_tag(input, inlen, sip);
    uint8_t sp[8];        speck_enc(sip, 8, sp);
    uint8_t cc[8];        chacha20_enc(sp, 8, cc);
    uint8_t p1[16];
    char cc_str[17]; for(int i=0;i<8;i++) sprintf(cc_str+i*2,"%02x",cc[i]);
    poly1305_tag((const uint8_t*)cc_str, 16, p1);
    uint8_t rc[16];       custom_rc_enc(p1, 16, rc);
    uint8_t gm[16];       gimli_enc(rc, 16, gm);
    uint8_t xd[16];       xoodoo_tag(gm, 16, xd);
    uint8_t b3[16];       blake3_enc(xd, 16, b3);
    uint8_t ck[16];       chaskey_tag(b3, 16, ck);
    char ck_str[33]; for(int i=0;i<16;i++) sprintf(ck_str+i*2,"%02x",ck[i]);
    char hmac_in[200]; snprintf(hmac_in, sizeof(hmac_in), "%s", ck_str);
    hmac_mac(hmac_in, 32, out);
}

static void rs_expand_keystream(const uint8_t *seed, size_t seedlen, uint8_t *ks, size_t needed) {
    size_t filled=0; uint32_t ctr=0;
    while(filled<needed){
        uint8_t block[seedlen+4];
        memcpy(block,seed,seedlen);
        block[seedlen]=(uint8_t)(ctr>>24); block[seedlen+1]=(uint8_t)(ctr>>16);
        block[seedlen+2]=(uint8_t)(ctr>>8); block[seedlen+3]=(uint8_t)ctr;
        uint8_t chunk[32]; rs_pipeline(block,seedlen+4,chunk);
        size_t take=needed-filled<32?needed-filled:32;
        memcpy(ks+filled,chunk,take); filled+=take; ctr++;
    }
}

static bool rs_encrypt(const uint8_t *key, size_t keylen, const uint8_t *plain, size_t plainlen, uint8_t *out, size_t *outlen) {
    uint8_t derived[32]; rs_pipeline(key,keylen,derived);
    *outlen=plainlen+4;
    uint8_t *ks=(uint8_t*)malloc(*outlen); if(!ks) return false;
    rs_expand_keystream(derived,32,ks,*outlen);
    out[0]=(uint8_t)((plainlen>>24)&0xFF)^ks[0];
    out[1]=(uint8_t)((plainlen>>16)&0xFF)^ks[1];
    out[2]=(uint8_t)((plainlen>>8)&0xFF)^ks[2];
    out[3]=(uint8_t)(plainlen&0xFF)^ks[3];
    for(size_t i=0;i<plainlen;i++) out[i+4]=plain[i]^ks[i+4];
    free(ks); return true;
}

static bool rs_decrypt(const uint8_t *key, size_t keylen, const uint8_t *ct, size_t ctlen, uint8_t *out, size_t *outlen) {
    if(ctlen<4) return false;
    uint8_t derived[32]; rs_pipeline(key,keylen,derived);
    uint8_t *ks=(uint8_t*)malloc(ctlen); if(!ks) return false;
    rs_expand_keystream(derived,32,ks,ctlen);
    size_t len=((size_t)(ct[0]^ks[0])<<24)|((size_t)(ct[1]^ks[1])<<16)|((size_t)(ct[2]^ks[2])<<8)|(size_t)(ct[3]^ks[3]);
    if(len>ctlen-4){ free(ks); return false; }
    for(size_t i=0;i<len;i++) out[i]=ct[i+4]^ks[i+4];
    *outlen=len; free(ks); return true;
}

}
#endif
