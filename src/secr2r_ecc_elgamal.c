#include "secr2r_ecc_elgamal.h"
#include <limits.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

static EC_GROUP *new_group(void) { return EC_GROUP_new_by_curve_name(NID_secp521r1); }
static int parse_point(const EC_GROUP *g, const uint8_t in[133], EC_POINT *p, BN_CTX *ctx) {
    return in && in[0] == 0x04 && EC_POINT_oct2point(g,p,in,133,ctx)==1 &&
           EC_POINT_is_at_infinity(g,p)==0 && EC_POINT_is_on_curve(g,p,ctx)==1;
}
static int point_out(const EC_GROUP *g,const EC_POINT *p,uint8_t out[133],BN_CTX *ctx) {
    return EC_POINT_point2oct(g,p,POINT_CONVERSION_UNCOMPRESSED,out,133,ctx)==133;
}
static int load_priv(const EC_GROUP *g,const uint8_t in[66],BIGNUM **dout) {
    BIGNUM *d=BN_bin2bn(in,66,NULL); const BIGNUM *n=EC_GROUP_get0_order(g);
    if(!d || BN_is_zero(d) || BN_is_negative(d) || BN_cmp(d,n)>=0) { BN_clear_free(d); return 0; }
    *dout=d; return 1;
}
int secr2r_eg_keygen(uint8_t priv[66],uint8_t pub[133]) {
    EC_GROUP *g=NULL; BN_CTX *ctx=NULL; BIGNUM *d=NULL; EC_POINT *q=NULL; int ok=0;
    if(!priv||!pub) return 0;
    g=new_group(); ctx=BN_CTX_new(); d=BN_new(); q=g?EC_POINT_new(g):NULL;
    if(!g||!ctx||!d||!q||BN_priv_rand_range(d,EC_GROUP_get0_order(g))!=1||BN_is_zero(d)||
       EC_POINT_mul(g,q,d,NULL,NULL,ctx)!=1||BN_bn2binpad(d,priv,66)!=66||!point_out(g,q,pub,ctx)) goto done;
    ok=1;
done: if(!ok){OPENSSL_cleanse(priv,66);OPENSSL_cleanse(pub,133);} BN_clear_free(d);EC_POINT_free(q);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;
}
static int embed_chunk(const EC_GROUP *g,const uint8_t *bytes,size_t len,EC_POINT *m,BN_CTX *ctx) {
    uint8_t buf[24]={0}; BIGNUM *x=NULL; unsigned c; int ok=0;
    if(len>24) return 0;
    if(len) memcpy(buf,bytes,len);
    x=BN_bin2bn(buf,24,NULL); if(!x) goto done;
    /* x = chunk*256 + counter. Try 256 possible low-byte counters. */
    for(c=0;c<256;c++) {
        if(BN_bin2bn(buf,24,x)==NULL || BN_lshift(x,x,8)!=1 || BN_add_word(x,c)!=1) goto done;
        if(EC_POINT_set_compressed_coordinates(g,m,x,0,ctx)==1 && EC_POINT_is_on_curve(g,m,ctx)==1) { ok=1; break; }
        ERR_clear_error();
    }
done: OPENSSL_cleanse(buf,sizeof(buf)); BN_clear_free(x); return ok;
}
int secr2r_eg_encrypt(const uint8_t pub[133],const uint8_t *pt,size_t plen,uint8_t *ct,size_t cap,size_t *ctlen) {
    EC_GROUP *g=NULL; BN_CTX *ctx=NULL; EC_POINT *q=NULL,*m=NULL,*c1=NULL,*c2=NULL,*tmp=NULL; BIGNUM *k=NULL; size_t chunks,need,off=5,i,at=0; int ok=0;
    if(ctlen) *ctlen=0;
    if(!pub||(!pt&&plen)||!ct||!ctlen||plen>UINT32_MAX) return 0;
    chunks=(plen+23)/24; if(chunks>(SIZE_MAX-5)/266) return 0; need=5+chunks*266; if(cap<need){*ctlen=need;return 0;}
    g=new_group();ctx=BN_CTX_new();q=g?EC_POINT_new(g):NULL;m=g?EC_POINT_new(g):NULL;c1=g?EC_POINT_new(g):NULL;c2=g?EC_POINT_new(g):NULL;tmp=g?EC_POINT_new(g):NULL;k=BN_new();
    if(!g||!ctx||!q||!m||!c1||!c2||!tmp||!k||!parse_point(g,pub,q,ctx)) goto done;
    ct[0]=SECR2R_EG_VERSION;ct[1]=(uint8_t)(plen>>24);ct[2]=(uint8_t)(plen>>16);ct[3]=(uint8_t)(plen>>8);ct[4]=(uint8_t)plen;
    for(i=0;i<chunks;i++) {
        size_t len=plen-at; if(len>24)len=24;
        if(!embed_chunk(g,pt?pt+at:NULL,len,m,ctx)) goto done;
        do { if(BN_priv_rand_range(k,EC_GROUP_get0_order(g))!=1) goto done; } while(BN_is_zero(k));
        if(EC_POINT_mul(g,c1,k,NULL,NULL,ctx)!=1 || EC_POINT_mul(g,tmp,NULL,q,k,ctx)!=1 ||
           EC_POINT_add(g,c2,m,tmp,ctx)!=1 || EC_POINT_is_at_infinity(g,c2)==1 ||
           !point_out(g,c1,ct+off,ctx)||!point_out(g,c2,ct+off+133,ctx)) goto done;
        off+=266;at+=len;
    }
    *ctlen=need;ok=1;
done: if(!ok&&ct&&cap)OPENSSL_cleanse(ct,cap<need?cap:need);BN_clear_free(k);EC_POINT_free(q);EC_POINT_free(m);EC_POINT_free(c1);EC_POINT_free(c2);EC_POINT_free(tmp);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;
}
int secr2r_eg_decrypt(const uint8_t priv[66],const uint8_t *ct,size_t ctlen,uint8_t *pt,size_t cap,size_t *ptlen) {
    EC_GROUP *g=NULL;BN_CTX *ctx=NULL;BIGNUM *d=NULL;EC_POINT *c1=NULL,*c2=NULL,*shared=NULL,*m=NULL;size_t plen,chunks,need,off=5,at=0,i;int ok=0;
    if(ptlen) *ptlen=0;
    if(!priv||!ct||!ptlen||ctlen<5||ct[0]!=SECR2R_EG_VERSION)return 0;
    plen=((size_t)ct[1]<<24)|((size_t)ct[2]<<16)|((size_t)ct[3]<<8)|(size_t)ct[4];chunks=(plen+23)/24;
    if(chunks>(SIZE_MAX-5)/266)return 0;
    need=5+chunks*266;
    if(ctlen!=need||cap<plen||(!pt&&plen))return 0;
    g=new_group();ctx=BN_CTX_new();c1=g?EC_POINT_new(g):NULL;c2=g?EC_POINT_new(g):NULL;shared=g?EC_POINT_new(g):NULL;m=g?EC_POINT_new(g):NULL;
    if(!g||!ctx||!c1||!c2||!shared||!m||!load_priv(g,priv,&d))goto done;
    for(i=0;i<chunks;i++) {
        uint8_t raw[25]; size_t len=plen-at;if(len>24)len=24;
        if(!parse_point(g,ct+off,c1,ctx)||!parse_point(g,ct+off+133,c2,ctx)||
           EC_POINT_mul(g,shared,NULL,c1,d,ctx)!=1||EC_POINT_invert(g,shared,ctx)!=1||
           EC_POINT_add(g,m,c2,shared,ctx)!=1||EC_POINT_is_at_infinity(g,m)==1)goto done;
        /* x-coordinate is chunk*256+counter; convert x to 25 bytes then drop counter. */
        { BIGNUM *x=BN_new(); if(!x||EC_POINT_get_affine_coordinates(g,m,x,NULL,ctx)!=1||BN_num_bits(x)>200||BN_bn2binpad(x,raw,25)!=25){BN_clear_free(x);goto done;} BN_clear_free(x); }
        memcpy(pt+at,raw,len); OPENSSL_cleanse(raw,sizeof(raw)); off+=266;at+=len;
    }
    *ptlen=plen;ok=1;
done:if(!ok&&pt&&cap)OPENSSL_cleanse(pt,cap);BN_clear_free(d);EC_POINT_free(c1);EC_POINT_free(c2);EC_POINT_free(shared);EC_POINT_free(m);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;
}
