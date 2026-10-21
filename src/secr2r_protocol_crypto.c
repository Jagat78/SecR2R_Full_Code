#include "secr2r_protocol_crypto.h"
#include <string.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* P-256 EC-ElGamal adapter. Wire format: version || uint32 length ||
 * repeated (C1[65] || C2[65]); each plaintext chunk is at most 16 bytes.
 * Embed chunk as x = (chunk << 8) + counter and search counter 0..255. */
#define CURVE_NID NID_X9_62_prime256v1
#define POINT_BYTES 65u
#define CHUNK_BYTES 16u
#define BLOCK_BYTES (2u * POINT_BYTES)
#define OVERHEAD 5u
#define VERSION 1u
static EC_GROUP *group_new(void) { return EC_GROUP_new_by_curve_name(CURVE_NID); }
static int point_parse(const EC_GROUP *g,const uint8_t in[65],EC_POINT *p,BN_CTX *ctx) {
 return in && in[0]==4 && EC_POINT_oct2point(g,p,in,65,ctx)==1 && EC_POINT_is_at_infinity(g,p)==0 && EC_POINT_is_on_curve(g,p,ctx)==1;
}
static int point_write(const EC_GROUP *g,const EC_POINT *p,uint8_t out[65],BN_CTX *ctx) {
 return EC_POINT_point2oct(g,p,POINT_CONVERSION_UNCOMPRESSED,out,65,ctx)==65;
}
static int embed(const EC_GROUP *g,const uint8_t *bytes,size_t len,EC_POINT *m,BN_CTX *ctx) {
 uint8_t buf[16]={0}; BIGNUM *x=BN_new(); int ok=0;
 if(!x||len>16) goto done; if(len)memcpy(buf,bytes,len);
 if(!BN_bin2bn(buf,16,x))goto done;
 for(unsigned c=0;c<256;c++) {
  if(!BN_bin2bn(buf,16,x)||BN_lshift(x,x,8)!=1||BN_add_word(x,c)!=1)goto done;
  if(EC_POINT_set_compressed_coordinates(g,m,x,0,ctx)==1 && EC_POINT_is_on_curve(g,m,ctx)==1){ok=1;break;}
  ERR_clear_error();
 }
done: OPENSSL_cleanse(buf,sizeof buf); BN_clear_free(x); return ok;
}
static int load_private(const EC_GROUP *g,const uint8_t priv[32],BIGNUM **out) {
 BIGNUM *d=BN_bin2bn(priv,32,NULL); const BIGNUM *n=EC_GROUP_get0_order(g);
 if(!d||BN_is_zero(d)||BN_is_negative(d)||BN_cmp(d,n)>=0){BN_clear_free(d);return 0;} *out=d;return 1;
}
static int encrypt_p256(const uint8_t pub[65],const uint8_t *pt,size_t plen,uint8_t *ct,size_t cap,size_t *ctlen) {
 EC_GROUP *g=NULL;BN_CTX *ctx=NULL;EC_POINT *q=NULL,*m=NULL,*c1=NULL,*c2=NULL,*tmp=NULL;BIGNUM *k=NULL;
 size_t chunks,need,off=5,at=0;int ok=0;
 if(ctlen)*ctlen=0;if(!pub||(!pt&&plen)||!ct||!ctlen||plen>UINT32_MAX)return 0;
 chunks=(plen+15)/16;if(chunks>(SIZE_MAX-5)/130)return 0;need=5+chunks*130;if(cap<need){*ctlen=need;return 0;}
 g=group_new();ctx=BN_CTX_new();q=g?EC_POINT_new(g):NULL;m=g?EC_POINT_new(g):NULL;c1=g?EC_POINT_new(g):NULL;c2=g?EC_POINT_new(g):NULL;tmp=g?EC_POINT_new(g):NULL;k=BN_new();
 if(!g||!ctx||!q||!m||!c1||!c2||!tmp||!k||!point_parse(g,pub,q,ctx))goto done;
 ct[0]=VERSION;ct[1]=(uint8_t)(plen>>24);ct[2]=(uint8_t)(plen>>16);ct[3]=(uint8_t)(plen>>8);ct[4]=(uint8_t)plen;
 for(size_t i=0;i<chunks;i++){size_t len=plen-at;if(len>16)len=16;
  if(!embed(g,pt?pt+at:NULL,len,m,ctx))goto done;
  do{if(BN_priv_rand_range(k,EC_GROUP_get0_order(g))!=1)goto done;}while(BN_is_zero(k));
  if(EC_POINT_mul(g,c1,k,NULL,NULL,ctx)!=1||EC_POINT_mul(g,tmp,NULL,q,k,ctx)!=1||EC_POINT_add(g,c2,m,tmp,ctx)!=1||EC_POINT_is_at_infinity(g,c2)==1||!point_write(g,c1,ct+off,ctx)||!point_write(g,c2,ct+off+65,ctx))goto done;
  off+=130;at+=len;
 }
 *ctlen=need;ok=1;
done:if(!ok&&ct&&cap)OPENSSL_cleanse(ct,cap<need?cap:need);BN_clear_free(k);EC_POINT_free(q);EC_POINT_free(m);EC_POINT_free(c1);EC_POINT_free(c2);EC_POINT_free(tmp);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;
}
static int decrypt_p256(const uint8_t priv[32],const uint8_t *ct,size_t ctlen,uint8_t *pt,size_t cap,size_t *ptlen) {
 EC_GROUP *g=NULL;BN_CTX *ctx=NULL;BIGNUM *d=NULL;EC_POINT *c1=NULL,*c2=NULL,*shared=NULL,*m=NULL;size_t plen,chunks,need,off=5,at=0;int ok=0;
 if(ptlen)*ptlen=0;if(!priv||!ct||!ptlen||ctlen<5||ct[0]!=VERSION)return 0;
 plen=((size_t)ct[1]<<24)|((size_t)ct[2]<<16)|((size_t)ct[3]<<8)|ct[4];chunks=(plen+15)/16;if(chunks>(SIZE_MAX-5)/130)return 0;need=5+chunks*130;
 if(ctlen!=need||cap<plen||(!pt&&plen))return 0;
 g=group_new();ctx=BN_CTX_new();c1=g?EC_POINT_new(g):NULL;c2=g?EC_POINT_new(g):NULL;shared=g?EC_POINT_new(g):NULL;m=g?EC_POINT_new(g):NULL;
 if(!g||!ctx||!c1||!c2||!shared||!m||!load_private(g,priv,&d))goto done;
 for(size_t i=0;i<chunks;i++){size_t len=plen-at;if(len>16)len=16;uint8_t raw[16];BIGNUM *x=BN_new();
  if(!x||!point_parse(g,ct+off,c1,ctx)||!point_parse(g,ct+off+65,c2,ctx)||EC_POINT_mul(g,shared,NULL,c1,d,ctx)!=1||EC_POINT_invert(g,shared,ctx)!=1||EC_POINT_add(g,m,c2,shared,ctx)!=1||EC_POINT_is_at_infinity(g,m)==1||EC_POINT_get_affine_coordinates(g,m,x,NULL,ctx)!=1||BN_rshift(x,x,8)!=1||BN_num_bits(x)>128||BN_bn2binpad(x,raw,16)!=16){BN_clear_free(x);OPENSSL_cleanse(raw,sizeof raw);goto done;}
  memcpy(pt+at,raw,len);OPENSSL_cleanse(raw,sizeof raw);BN_clear_free(x);off+=130;at+=len;
 }
 *ptlen=plen;ok=1;
done:if(!ok&&pt&&cap)OPENSSL_cleanse(pt,cap);BN_clear_free(d);EC_POINT_free(c1);EC_POINT_free(c2);EC_POINT_free(shared);EC_POINT_free(m);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;
}
int secr2r_enc_lc(const uint8_t pub[65],const uint8_t *lc,size_t n,uint8_t *out,size_t cap,size_t *outn){return encrypt_p256(pub,lc,n,out,cap,outn);}
int secr2r_dec_lc(const uint8_t priv[32],const uint8_t *ct,size_t n,uint8_t *out,size_t cap,size_t *outn){return decrypt_p256(priv,ct,n,out,cap,outn);}
int secr2r_enc_c5_payload(const uint8_t pub[65],const uint8_t *p,size_t n,uint8_t *out,size_t cap,size_t *outn){return encrypt_p256(pub,p,n,out,cap,outn);}
int secr2r_dec_c5_payload(const uint8_t priv[32],const uint8_t *ct,size_t n,uint8_t *out,size_t cap,size_t *outn){return decrypt_p256(priv,ct,n,out,cap,outn);}
