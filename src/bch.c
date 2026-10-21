#include "bch_fe.h"
#include <string.h>

/* GF(2^8), primitive polynomial 0x11D, alpha=2 */
static uint8_t gf_exp[512];
static int16_t gf_log[256];
static int initialized = 0;

static uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (!a || !b) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}
static uint8_t gf_div(uint8_t a, uint8_t b) {
    if (!b) return 0;
    if (!a) return 0;
    int d = (int)gf_log[a] - (int)gf_log[b];
    if (d < 0) d += 255;
    return gf_exp[d];
}
static uint8_t gf_square(uint8_t a) { return gf_mul(a,a); }

void bch_fe_init(void) {
    if (initialized) return;
    for (int i=0;i<256;i++) gf_log[i] = -1;
    uint16_t x=1;
    for (int i=0;i<255;i++) {
        gf_exp[i]=(uint8_t)x;
        gf_log[x]=i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D;
    }
    for (int i=255;i<512;i++) gf_exp[i]=gf_exp[i-255];
    initialized=1;
}

static void syndrome_vector(const uint8_t bits[BCH_N], uint8_t s[2*BCH_T+1]) {
    memset(s,0,2*BCH_T+1);
    for (int j=1;j<=2*BCH_T;j++) {
        uint8_t xj=gf_exp[j], value=0, power=1;
        for (int i=0;i<BCH_N;i++) {
            if (bits[i]) value ^= power;
            power=gf_mul(power,xj);
        }
        s[j]=value;
    }
}

void bch_secure_sketch_enroll(const uint8_t bits[BCH_N],
                              uint8_t helper[BCH_HELPER_SYMBOLS]) {
    uint8_t s[2*BCH_T+1];
    bch_fe_init();
    syndrome_vector(bits,s);
    for (int k=0;k<BCH_HELPER_SYMBOLS;k++) helper[k]=s[1+2*k];
}

static void helper_to_syndromes(const uint8_t helper[BCH_HELPER_SYMBOLS],
                                uint8_t s[2*BCH_T+1]) {
    memset(s,0,2*BCH_T+1);
    for (int k=0;k<BCH_HELPER_SYMBOLS;k++) {
        int j=1+2*k;
        s[j]=helper[k];
    }
    for (int j=2;j<=2*BCH_T;j+=2) s[j]=gf_square(s[j/2]);
}

static uint8_t poly_eval(const uint8_t *p, int len, uint8_t x) {
    uint8_t y=0;
    for (int i=len-1;i>=0;i--) y=gf_mul(y,x)^p[i];
    return y;
}

/* Berlekamp-Massey; input sequence is the reversed syndrome sequence,
   matching the convention used by the supplied Python implementation. */
static int berlekamp_massey(const uint8_t S[2*BCH_T], uint8_t C[BCH_T+1]) {
    uint8_t B[BCH_T+1]={0}, T[BCH_T+1]={0};
    memset(C,0,BCH_T+1);
    C[0]=1; B[0]=1;
    int L=0, m=1;
    uint8_t b=1;
    for (int n=0;n<2*BCH_T;n++) {
        uint8_t d=S[n];
        for (int i=1;i<=L;i++) if (C[i]) d ^= gf_mul(C[i],S[n-i]);
        if (!d) { m++; continue; }
        memcpy(T,C,BCH_T+1);
        uint8_t coef=gf_div(d,b);
        for (int j=0;j<=BCH_T-m;j++) if (B[j]) C[j+m] ^= gf_mul(coef,B[j]);
        if (2*L <= n) {
            L=n+1-L;
            memcpy(B,T,BCH_T+1);
            b=d;
            m=1;
        } else m++;
    }
    return L;
}

int bch_secure_sketch_reconstruct(const uint8_t noisy[BCH_N],
                                  const uint8_t helper[BCH_HELPER_SYMBOLS],
                                  uint8_t corrected[BCH_N],
                                  unsigned *num_corrected) {
    uint8_t sn[2*BCH_T+1], se[2*BCH_T+1], diff[2*BCH_T+1];
    uint8_t seq[2*BCH_T], locator[BCH_T+1];
    bch_fe_init();
    syndrome_vector(noisy,sn);
    helper_to_syndromes(helper,se);
    for (int j=1;j<=2*BCH_T;j++) diff[j]=sn[j]^se[j];

    memcpy(corrected,noisy,BCH_N);
    int allzero=1;
    for (int j=1;j<=2*BCH_T;j++) if (diff[j]) {allzero=0;break;}
    if (allzero) { if(num_corrected)*num_corrected=0; return 1; }

    for (int i=0;i<2*BCH_T;i++) seq[i]=diff[2*BCH_T-i];
    memset(locator,0,sizeof(locator));
    int degree=berlekamp_massey(seq,locator);
    if (degree<1 || degree>BCH_T) {if(num_corrected)*num_corrected=0;return 0;}

    unsigned roots=0;
    for (int pos=0;pos<BCH_N;pos++) {
        uint8_t x=gf_exp[pos];
        if (poly_eval(locator,degree+1,x)==0) {
            corrected[pos]^=1;
            roots++;
        }
    }
    if (num_corrected) *num_corrected=roots;
    if (roots != (unsigned)degree) return 0;

    uint8_t sc[2*BCH_T+1];
    syndrome_vector(corrected,sc);
    for (int j=1;j<=2*BCH_T;j++) if (sc[j]!=se[j]) return 0;
    return 1;
}

void toeplitz_extract_128(const uint8_t input[PUF_BITS],
                          const uint8_t seed[TOEPLITZ_SEED_BITS],
                          uint8_t output[TOEPLITZ_OUT_BITS]) {
    for (int i=0;i<TOEPLITZ_OUT_BITS;i++) {
        uint8_t bit=0;
        for (int j=0;j<PUF_BITS;j++) bit ^= (seed[i+j] & input[j]);
        output[i]=bit;
    }
}
