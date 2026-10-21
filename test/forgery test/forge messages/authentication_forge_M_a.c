#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fuzzy_extractor.h"
#include "secr2r_hash.h"
#include "secr2r_protocol_crypto.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <time.h>
#include <stdint.h>

/* Step 1 only: Robot A obtains a different recorded readout for the same uid,
 * then tests fuzzy reconstruction. This is a dataset replay, not live SRAM capture.
 * Usage: ./bin/authentication data/crps.csv data/selected_cells.csv robot_A.csv robot_B.csv server.csv
 */
#define MAX_LINE (1024*16)
#define MAX_FIELDS 16
#define RAW_BYTES 512
/* In --forge-ma mode, stop immediately after server C6 validation. */
static int g_stop_after_c6 = 0;
typedef struct { unsigned offset, bit; int crypto; } Cell;
static int csv_fields(char *s,char **out,int max){
 size_t slen=strlen(s); while(slen && (s[slen-1]=='\n' || s[slen-1]=='\r')) s[--slen]='\0';
 int n=0; char *p=s;
 while(*p && n<max){
  if(*p=='"'){p++;out[n++]=p;char *w=p;while(*p){if(*p=='"'){if(p[1]=='"'){*w++='"';p+=2;}else{p++;break;}}else *w++=*p++;}*w=0;while(*p&&*p!=',')p++;if(*p==',')*p++=0;}
  else{out[n++]=p;while(*p&&*p!=',')p++;if(*p==',')*p++=0;}
 }
 return n;
}
static int hexdec(const char*s,unsigned char*out,size_t cap,size_t *len){
 size_t n=strlen(s);if(n%2||n/2>cap)return 0;
 for(size_t i=0;i<n/2;i++){unsigned x;if(sscanf(s+2*i,"%2x",&x)!=1)return 0;out[i]=(unsigned char)x;}*len=n/2;return 1;
}
static int read_map(const char*path,Cell c[512]){
 FILE*f=fopen(path,"r");if(!f){perror(path);return 0;}char *line=NULL;size_t cap=0;ssize_t z=getline(&line,&cap,f);unsigned n=0;
 while((z=getline(&line,&cap,f))>=0){char *v[MAX_FIELDS];int k=csv_fields(line,v,MAX_FIELDS);if(k<5)continue;c[n].offset=(unsigned)strtoul(v[2],0,10);c[n].bit=(unsigned)strtoul(v[3],0,10);c[n].crypto=(!strcmp(v[4],"True")||!strcmp(v[4],"true")||!strcmp(v[4],"TRUE")||!strcmp(v[4],"1"));if(c[n].offset>=512||c[n].bit>7){free(line);fclose(f);return 0;}n++;}
 free(line);fclose(f);return n==512;
}
static int load_robot(const char*path,char*uid,size_t uidcap,unsigned char fp[510],fe_helper_t*h,unsigned char psi[16],unsigned char rho[80]){
 FILE*f=fopen(path,"r");if(!f){perror(path);return 0;}char line[8192];fgets(line,sizeof line,f);int havefp=0,havetheta=0,havepsi=0,haverho=0;
 while(fgets(line,sizeof line,f)){char *v[MAX_FIELDS];int n=csv_fields(line,v,MAX_FIELDS);if(n<3)continue;if(strlen(v[0])>=uidcap)continue;strncpy(uid,v[0],uidcap-1);
  size_t z=0;unsigned char tmp[2048];
  if(!strcmp(v[1],"FP_selected_bits_private")){if(strlen(v[2])!=510)continue;for(int i=0;i<510;i++){if(v[2][i]!='0'&&v[2][i]!='1')return 0;fp[i]=(unsigned char)(v[2][i]-'0');}havefp=1;}
  else if(!strcmp(v[1],"Theta_helper")){if(!hexdec(v[2],tmp,sizeof tmp,&z)||z!=FE_HELPER_BYTES||!fe_helper_deserialize(tmp,h))return 0;memcpy(rho,tmp+2*BCH_HELPER_SYMBOLS,FE_SEED_BYTES);havetheta=1;}
  else if(!strcmp(v[1],"Psi_private")){if(!hexdec(v[2],psi,16,&z)||z!=16)return 0;havepsi=1;}
  else if(!strcmp(v[1],"rho_seed")){if(!hexdec(v[2],rho,80,&z)||z!=80)return 0;haverho=1;}
 }
 fclose(f);return havefp&&havetheta&&havepsi;
}
static int parse_data(const char*s,unsigned char raw[512]){
 const char*p=s;for(int i=0;i<512;i++){char*e;errno=0;long x=strtol(p,&e,10);if(e==p||errno||x<0||x>255)return 0;raw[i]=(unsigned char)x;p=e;if(i<511){if(*p!=',')return 0;p++;}}return 1;
}
static int make_fp(const unsigned char raw[512],const Cell c[512],unsigned char fp[510]){
 unsigned j=0;for(unsigned i=0;i<512;i++)if(c[i].crypto){if(j>=510)return 0;fp[j++]=(raw[c[i].offset]>>(7-c[i].bit))&1;}return j==510;
}
static unsigned hd(const unsigned char*a,const unsigned char*b,unsigned n){unsigned d=0;for(unsigned i=0;i<n;i++)d+=(a[i]!=b[i]);return d;}

static int get_param(const char *path, const char *key, char *out, size_t outcap) {
 FILE *f=fopen(path,"r"); if(!f){perror(path);return 0;}
 char line[16384]; if(!fgets(line,sizeof line,f)){fclose(f);return 0;}
 while(fgets(line,sizeof line,f)) { char *v[MAX_FIELDS]; int n=csv_fields(line,v,MAX_FIELDS); const char *val=NULL; if(n>=3 && !strcmp(v[1],key)) val=v[2]; else if(n>=2 && !strcmp(v[0],key)) val=v[1]; if(val) { size_t z=strlen(val); if(z>=outcap){fclose(f);return 0;} memcpy(out,val,z+1); fclose(f); return 1; } }
 fclose(f); return 0;
}
static int read_hex_param(const char *path,const char *key,unsigned char *out,size_t want) {
 char val[8192]; size_t n=0; return get_param(path,key,val,sizeof val)&&hexdec(val,out,want,&n)&&n==want;
}
static int save_hex_csv(const char *dir,const char *name,const char *label,const unsigned char *data,size_t len) {
 char path[1024]; if(snprintf(path,sizeof path,"%s/%s.csv",dir,name)>=(int)sizeof path)return 0;
 FILE *f=fopen(path,"w"); if(!f){perror(path);return 0;} fprintf(f,"parameter,value_hex\n%s,",label);
 for(size_t i=0;i<len;i++) fprintf(f,"%02x",data[i]);
 fputc('\n',f);
 int ok=fclose(f)==0;
 return ok;
}
static int point_mul_base(const unsigned char scalar[32],unsigned char out[65]) {
 int ok=0; EC_GROUP *g=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); BN_CTX *ctx=BN_CTX_new(); BIGNUM *k=BN_bin2bn(scalar,32,NULL); EC_POINT *q=g?EC_POINT_new(g):NULL;
 if(g&&ctx&&k&&q&&!BN_is_zero(k)&&BN_cmp(k,EC_GROUP_get0_order(g))<0&&EC_POINT_mul(g,q,k,NULL,NULL,ctx)==1&&EC_POINT_point2oct(g,q,POINT_CONVERSION_UNCOMPRESSED,out,65,ctx)==65)ok=1;
 BN_clear_free(k);EC_POINT_free(q);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;
}
static int point_mul_point(const unsigned char scalar[32],const unsigned char point[65],unsigned char out[65]) {
 int ok=0; EC_GROUP *g=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); BN_CTX *ctx=BN_CTX_new(); BIGNUM *k=BN_bin2bn(scalar,32,NULL); EC_POINT *p=g?EC_POINT_new(g):NULL,*q=g?EC_POINT_new(g):NULL;
 if(g&&ctx&&k&&p&&q&&!BN_is_zero(k)&&BN_cmp(k,EC_GROUP_get0_order(g))<0&&point[0]==4&&EC_POINT_oct2point(g,p,point,65,ctx)==1&&EC_POINT_is_on_curve(g,p,ctx)==1&&EC_POINT_mul(g,q,NULL,p,k,ctx)==1&&EC_POINT_point2oct(g,q,POINT_CONVERSION_UNCOMPRESSED,out,65,ctx)==65)ok=1;
 BN_clear_free(k);EC_POINT_free(p);EC_POINT_free(q);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;
}
static int random_scalar(unsigned char out[32]) {
 EC_GROUP *g=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); BIGNUM *k=BN_new(); int ok=0;
 if(g&&k&&BN_priv_rand_range(k,EC_GROUP_get0_order(g))==1&&!BN_is_zero(k)&&BN_bn2binpad(k,out,32)==32)ok=1;
 BN_clear_free(k);EC_GROUP_free(g);return ok;
}

/* Server-side processing of M_A (Figure 4, AS -> R_b, step 2).
 * Figure 5 in the supplied screenshots is R_b -> AS (M_B), so the server
 * operation for M_A is taken from Figure 4. */
static int point_add(const unsigned char a[65],const unsigned char b[65],unsigned char out[65]) {
 int ok=0; EC_GROUP *g=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); BN_CTX *ctx=BN_CTX_new();
 EC_POINT *pa=g?EC_POINT_new(g):NULL,*pb=g?EC_POINT_new(g):NULL,*sum=g?EC_POINT_new(g):NULL;
 if(g&&ctx&&pa&&pb&&sum&&a[0]==4&&b[0]==4&&EC_POINT_oct2point(g,pa,a,65,ctx)==1&&EC_POINT_oct2point(g,pb,b,65,ctx)==1&&EC_POINT_is_on_curve(g,pa,ctx)==1&&EC_POINT_is_on_curve(g,pb,ctx)==1&&EC_POINT_add(g,sum,pa,pb,ctx)==1&&EC_POINT_is_at_infinity(g,sum)==0&&EC_POINT_point2oct(g,sum,POINT_CONVERSION_UNCOMPRESSED,out,65,ctx)==65)ok=1;
 EC_POINT_free(pa);EC_POINT_free(pb);EC_POINT_free(sum);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;
}
static int read_ma_csv(const char *path,char *ida,size_t idcap,char *idb,size_t idbcap,
 unsigned char c1[65],unsigned char c3[32],unsigned char *c5,size_t c5cap,size_t *c5len,
 unsigned char c6[32],unsigned char ta[8]) {
 FILE *f=fopen(path,"r"); if(!f){perror(path);return 0;} char *line=NULL;size_t cap=0;int ok=0; char *v[MAX_FIELDS];
 if(getline(&line,&cap,f)<0||getline(&line,&cap,f)<0)goto done;
 int n=csv_fields(line,v,MAX_FIELDS); if(n<7)goto done;
 if(strlen(v[0])>=idcap||strlen(v[1])>=idbcap)goto done;
 strcpy(ida,v[0]);strcpy(idb,v[1]);
 unsigned char tmp[8192];size_t z=0;
 if(!hexdec(v[2],c1,65,&z)||z!=65||!hexdec(v[3],c3,32,&z)||z!=32||
    !hexdec(v[4],c5,c5cap,c5len)||!hexdec(v[5],c6,32,&z)||z!=32||!hexdec(v[6],ta,8,&z)||z!=8)goto done;
 (void)tmp;ok=1;
done: free(line);fclose(f);return ok;
}
static int server_process_mb(const char *mb_path,const char *server_csv,const char *robotA_csv,const char *robotB_csv);
static int point_sub(const unsigned char a[65],const unsigned char b[65],unsigned char out[65]);
static int robot_A_process_m2s(const char *m2s_path,const char *robotA_csv) {
 /* Figure 7: Robot A verifies M_2s and compares its derived session key with
  * Robot B's sessionkey.csv. Coordinates/scalars use fixed-width P-256 encoding. */
 char line[16384],*v[MAX_FIELDS],ida[256],idb[256],uid[256]="";
 unsigned char y5[32],y6[32],y7[65],y8recv[32],ts[8],c2a[65],ba[65],bb[65],k2a[32];
 unsigned char us[32],usp[65],c[65],shared[65],hw2bb[32],mix[256],hc[32],y8calc[32],key[32],key_stored[32];
 FILE *f=fopen(m2s_path,"r"); if(!f){perror(m2s_path);return 0;}
 if(!fgets(line,sizeof line,f)||!fgets(line,sizeof line,f)){fclose(f);return 0;}
 int n=csv_fields(line,v,MAX_FIELDS);size_t z=0;
 if(n<7||strlen(v[0])>=sizeof ida||strlen(v[1])>=sizeof idb||
    !hexdec(v[2],y5,32,&z)||z!=32||!hexdec(v[3],y6,32,&z)||z!=32||
    !hexdec(v[4],y7,65,&z)||z!=65||!hexdec(v[5],y8recv,32,&z)||z!=32||!hexdec(v[6],ts,8,&z)||z!=8){fclose(f);fprintf(stderr,"Robot A: malformed M_2s\n");return 0;}
 strcpy(ida,v[0]);strcpy(idb,v[1]);fclose(f);
 {FILE *af=fopen(robotA_csv,"r");if(!af)return 0;if(fgets(line,sizeof line,af)&&fgets(line,sizeof line,af)){n=csv_fields(line,v,MAX_FIELDS);if(n>0&&strlen(v[0])<sizeof uid)strcpy(uid,v[0]);}fclose(af);}
 if(strcmp(idb,uid)){fprintf(stderr,"Robot A: M_2s recipient ID mismatch\n");return 0;}
 {uint64_t now=(uint64_t)time(NULL),tm=0;for(int i=0;i<8;i++)tm=(tm<<8)|ts[i];if(now<tm||now-tm>60){fprintf(stderr,"Robot A: M_2s timestamp freshness check failed\n");return 0;}}
 if(!read_hex_param("auth_outputs/server/C2_A_server.csv","C2_A_prime",c2a,65)||
    !read_hex_param("auth_outputs/A/B_A_star.csv","B_A_star",ba,65)||
    !read_hex_param("auth_outputs/robot_B/B_B_star.csv","B_B_star",bb,65)||
    !read_hex_param("auth_outputs/A/k2_A_private.csv","k2_A_private",k2a,32)){
   fprintf(stderr,"Robot A: required Figure-7 context missing\n");return 0;
 }
 /* u_s* = Y5s XOR x(C2a). */
 for(int i=0;i<32;i++)us[i]=y5[i]^c2a[1+i];
 if(!point_mul_base(us,usp)||!point_sub(y7,usp,c)){fprintf(stderr,"Robot A: u_s* or C calculation failed\n");return 0;}
 /* h(W2b(x)||B_b*) = Y6s XOR h(u_s*||B_b*||B_a*). */
 {size_t at=0;memcpy(mix+at,us,32);at+=32;memcpy(mix+at,bb,65);at+=65;memcpy(mix+at,ba,65);at+=65;
  unsigned char hmix[32];if(!secr2r_h(mix,at,hmix))return 0;
  for(int i=0;i<32;i++)hw2bb[i]=y6[i]^hmix[i];}
 /* Independently derive h(W2b(x)||B_b*) from the protocol context is not
  * possible from M_2s alone. Figure 7 defines it through Y6s; the relation is
  * checked by using that recovered value in Y8*. */
 if(!secr2r_h(c2a+1,32,hc))return 0;
 {size_t at=0;memcpy(mix+at,hw2bb,32);at+=32;memcpy(mix+at,us,32);at+=32;
  {unsigned char m[97];memcpy(m,c2a+1,32);memcpy(m+32,ba,65);if(!secr2r_h(m,sizeof m,hc))return 0;}
  memcpy(mix+at,hc,32);at+=32;memcpy(mix+at,c,65);at+=65;memcpy(mix+at,ts,8);at+=8;
  if(!secr2r_h(mix,at,y8calc)||memcmp(y8calc,y8recv,32)){fprintf(stderr,"Robot A: Y8* verification failed\n");return 0;}}
 /* Figure 7 session key uses the ECDH point [k2a]C. This matches Robot B's
  * [v2b]C4 because C4=[k2a]P and C=[v2b]P. */
 {unsigned char hca[32],m[256];size_t at=0;
  if(!point_mul_point(k2a,c,shared)){fprintf(stderr,"Robot A: shared ECDH point calculation failed\n");return 0;}
  memcpy(m,c2a+1,32);memcpy(m+32,ba,65);if(!secr2r_h(m,97,hca))return 0;
  memcpy(m+at,hca,32);at+=32;memcpy(m+at,hw2bb,32);at+=32;memcpy(m+at,shared,65);at+=65;
  if(!secr2r_h(m,at,key))return 0;}
 if(!read_hex_param("sessionkey.csv","SK_B",key_stored,32)&&!read_hex_param("sessionkey.csv","sessionkey",key_stored,32)){
   fprintf(stderr,"Robot A: cannot read Robot B key from sessionkey.csv\n");return 0;}
 /* Print both 32-byte session keys to the terminal for reproducible debugging. */
 printf("\n========== SESSION KEY COMPARISON ==========\n");
 printf("Session key computed by Robot A (SK_A): ");
 for(size_t i=0;i<sizeof key;i++) printf("%02x", key[i]);
 printf("\nSession key computed by Robot B (SK_B): ");
 for(size_t i=0;i<sizeof key_stored;i++) printf("%02x", key_stored[i]);
 printf("\n");
 if(memcmp(key,key_stored,32)!=0){
   printf("SK_A == SK_B: NO\n===========================================\n");
   save_hex_csv("auth_outputs/robot_A","SessionKey_A_computed","SK_A",key,32);
   fprintf(stderr,"Robot A: session-key mismatch; authentication FAIL\n");return 0;
 }
 printf("SK_A == SK_B: YES\n===========================================\n");
 if(mkdir("auth_outputs",0775)!=0&&errno!=EEXIST)return 0;
 if(mkdir("auth_outputs/robot_A",0775)!=0&&errno!=EEXIST)return 0;
 if(!save_hex_csv("auth_outputs/robot_A","M2s_Y8s_check","Y8s_computed",y8calc,32)||!save_hex_csv("auth_outputs/robot_A","C_shared","C_shared",c,65)||!save_hex_csv("auth_outputs/robot_A","SessionKey_A_computed","SK_A",key,32))return 0;
 printf("Robot A Figure-7 processing: PASS; freshness, recipient, C calculation, Y8 verification and session-key comparison passed.\n");(void)ida;return 1;
}

static int robot_B_process_m1s(const char*,const char*,const char*,const char*,const char*,const char*);
static int server_process_ma(const char *ma_path,const char *server_csv,const char *robotA_csv,const char *robotB_csv,const char *dataset,const char *map_path) {
 unsigned char s[32],pub[65],c1[65],c2[65],c3[32],c4[65],c5[4096],c6_recv[32],c6_calc[32],ta[8],t1[8];
 unsigned char hstar[32],ba[65],bb[65],bb_stored[65],ba_stored[65],payload[256],c2y_in[32],lc_b[32],elc_b[4096];
 unsigned char ns[32],y1[32],y2[32],y3[65],y4[32],hash1[32],hash2[32],buf[512];
 char ida[256],idb[256],a_uid[256],b_uid[256],outdir[1024]="auth_outputs/server";size_t c5len=0,plen=0,elclen=0;int ok=0;
 if(!read_ma_csv(ma_path,ida,sizeof ida,idb,sizeof idb,c1,c3,c5,sizeof c5,&c5len,c6_recv,ta)) {fprintf(stderr,"Server: cannot parse M_A CSV.\n");return 0;}
 if(!read_hex_param(server_csv,"s_private_scalar",s,32)||!read_hex_param(server_csv,"Pub_public_point",pub,65)||
    !read_hex_param(robotA_csv,"B_public_point",ba_stored,65)||!read_hex_param(robotB_csv,"B_public_point",bb_stored,65)) {fprintf(stderr,"Server: missing server/robot list parameters.\n");return 0;}
 if(!get_param(robotA_csv,"ID",a_uid,sizeof a_uid)) { /* Registration CSV may use uid as its first column. */
   FILE *af=fopen(robotA_csv,"r");if(af){char row[8192];if(fgets(row,sizeof row,af)&&fgets(row,sizeof row,af)){char *v[MAX_FIELDS];int n=csv_fields(row,v,MAX_FIELDS);if(n>0&&strlen(v[0])<sizeof a_uid)strcpy(a_uid,v[0]);}fclose(af);}
 }
 if(strcmp(ida,a_uid)!=0){fprintf(stderr,"Server: M_A sender ID does not match robot_A.csv.\n");return 0;}
 { FILE *bf=fopen(robotB_csv,"r"); if(bf){char row[8192];if(fgets(row,sizeof row,bf)&&fgets(row,sizeof row,bf)){char *v[MAX_FIELDS];int n=csv_fields(row,v,MAX_FIELDS);if(n>0&&strlen(v[0])<sizeof b_uid)strcpy(b_uid,v[0]);}fclose(bf);} }
 if(strcmp(idb,b_uid)!=0){fprintf(stderr,"Server: peer ID in M_A does not match robot_B.csv.\n");return 0;}
 /* Figure 4 freshness check. Delta-T is set to 60 seconds for this test harness. */
 { uint64_t ta_sec=0,now=(uint64_t)time(NULL);for(int i=0;i<8;i++)ta_sec=(ta_sec<<8)|ta[i];if(now<ta_sec||now-ta_sec>60){fprintf(stderr,"Server: timestamp outside configured 60-second freshness window.\n");return 0;}for(int i=7;i>=0;i--){t1[i]=(unsigned char)(now&255);now>>=8;} }
 if(!point_mul_point(s,c1,c2)){fprintf(stderr,"Server: invalid C1 or failed C2' computation.\n");return 0;}
 for(int i=0;i<32;i++)hstar[i]=c3[i]^c2[1+i];
 if(!point_mul_base(hstar,ba)){fprintf(stderr,"Server: failed B_A' computation.\n");return 0;}
 if(memcmp(ba,ba_stored,65)!=0){fprintf(stderr,"Server: B_A' is not present in robot list.\n");return 0;}
 if(!secr2r_dec_c5_payload(s,c5,c5len,payload,sizeof payload,&plen)||plen!=162){fprintf(stderr,"Server: C5 decryption/length check failed.\n");return 0;}
 memcpy(bb,payload,65);memcpy(c2y_in,payload+65,32);memcpy(c4,payload+97,65);
 if(memcmp(c2y_in,c2+33,32)!=0){fprintf(stderr,"Server: decrypted C2'(y) mismatch.\n");return 0;}
 if(memcmp(bb,bb_stored,65)!=0){fprintf(stderr,"Server: decrypted B_B' is not present in robot list.\n");return 0;}
 {size_t n=0;unsigned char *m=malloc(32+65+65+32+65+c5len+8);if(!m)return 0;
  memcpy(m+n,hstar,32);n+=32;memcpy(m+n,c1,65);n+=65;memcpy(m+n,c2,65);n+=65;memcpy(m+n,c3,32);n+=32;memcpy(m+n,c4,65);n+=65;memcpy(m+n,c5,c5len);n+=c5len;memcpy(m+n,ta,8);n+=8;
  int hh=secr2r_h(m,n,c6_calc);free(m);if(!hh)return 0; }
 if(memcmp(c6_calc,c6_recv,32)!=0){fprintf(stderr,"Server: C6 verification failed.\n");return 0;}
 if(g_stop_after_c6){printf("Server M_A validation through C6: PASS. Later protocol stages intentionally skipped.\n");return 1;}
 { char val[8192];
   if(!get_param(robotB_csv,"ELC_ciphertext",val,sizeof val) && !get_param(robotB_csv,"ELC_stored",val,sizeof val)) {fprintf(stderr,"Server: missing robot B ELC.\n");return 0;}
   if(!hexdec(val,elc_b,sizeof elc_b,&elclen)||!secr2r_dec_lc(s,elc_b,elclen,lc_b,sizeof lc_b,&plen)||plen!=32){fprintf(stderr,"Server: ELC_B decryption failed.\n");return 0;}
 }
 if(!random_scalar(ns)){fprintf(stderr,"Server: random n_s generation failed.\n");return 0;}
 for(int i=0;i<32;i++)y1[i]=ns[i]^lc_b[i];
 memcpy(buf,c2+1,32);memcpy(buf+32,ba,65);if(!secr2r_h(buf,97,hash1))return 0;
 memcpy(buf,ns,32);memcpy(buf+32,bb,65);if(!secr2r_h(buf,97,hash2))return 0;
 for(int i=0;i<32;i++)y2[i]=hash1[i]^hash2[i];
 {unsigned char nsP[65];if(!point_mul_base(ns,nsP)||!point_add(nsP,c4,y3)){fprintf(stderr,"Server: Y3 point calculation failed.\n");return 0;}}
 {unsigned char *m=malloc(32+32+65+8);if(!m)return 0;size_t n=0;memcpy(m+n,ns,32);n+=32;memcpy(m+n,hash1,32);n+=32;memcpy(m+n,c4,65);n+=65;memcpy(m+n,t1,8);n+=8;int hh=secr2r_h(m,n,y4);free(m);if(!hh)return 0;}
 if(mkdir("auth_outputs",0775)!=0&&errno!=EEXIST)return 0;
 if(mkdir(outdir,0775)!=0&&errno!=EEXIST)return 0;
 if(!save_hex_csv(outdir,"C2_A_server","C2_A_prime",c2,65)||!save_hex_csv(outdir,"H_A_server","H_ID_s_prime",hstar,32)||
    !save_hex_csv(outdir,"B_A_server_check","B_A_prime",ba,65)||!save_hex_csv(outdir,"B_B_decrypted","B_B_prime",bb,65)||
    !save_hex_csv(outdir,"C4_A_decrypted","C4_A_prime",c4,65)||!save_hex_csv(outdir,"C6_A_server_check","C6_A_prime",c6_calc,32)||
    !save_hex_csv(outdir,"LC_B_decrypted","LC_B",lc_b,32)||!save_hex_csv(outdir,"n_s_private","n_s",ns,32)||
    !save_hex_csv(outdir,"Y1_s","Y1_s",y1,32)||!save_hex_csv(outdir,"Y2_s","Y2_s",y2,32)||
    !save_hex_csv(outdir,"Y3_s","Y3_s",y3,65)||!save_hex_csv(outdir,"Y4_s","Y4_s",y4,32)||
    !save_hex_csv(outdir,"T1_s","T1_s_unix_seconds_be",t1,8))return 0;
 {char path[1024];snprintf(path,sizeof path,"%s/M1_A_to_B.csv",outdir);FILE*f=fopen(path,"w");if(!f){perror(path);return 0;}
  fprintf(f,"sender_id,recipient_id,Y1_s_hex,Y2_s_hex,Y3_s_hex,Y4_s_hex,T1_s_hex\n%s,%s,",ida,idb);
  const unsigned char *parts[]={y1,y2,y3,y4,t1};size_t lens[]={32,32,65,32,8};for(int j=0;j<5;j++){if(j)fputc(',',f);for(size_t i=0;i<lens[j];i++)fprintf(f,"%02x",parts[j][i]);}fputc('\n',f);if(fclose(f)!=0)return 0;}
 printf("Server Figure-4 processing: PASS; freshness, A/B list checks, C5 decryption, and C6 verification passed. M1_A_to_B.csv written to %s.\n",outdir); if(!robot_B_process_m1s("auth_outputs/server/M1_A_to_B.csv",dataset,map_path,server_csv,robotA_csv,robotB_csv)){fprintf(stderr,"Robot B rejected M1s.\n");return 0;} ok=1;return ok;
}


/* Load a two-column forge_robot_A_parameters CSV. Unlike registration CSVs,
 * this file has no header: every row is parameter_name,hex_value. */
static int get_forge_param(const char *path, const char *key, char *out, size_t outcap) {
 FILE *f=fopen(path,"r"); if(!f){perror(path);return 0;}
 char line[16384];
 while(fgets(line,sizeof line,f)) {
   char *v[MAX_FIELDS]; int n=csv_fields(line,v,MAX_FIELDS);
   if(n>=2 && !strcmp(v[0],key)) {
     size_t z=strlen(v[1]);
     if(z>=outcap){fclose(f);return 0;}
     memcpy(out,v[1],z+1);fclose(f);return 1;
   }
 }
 fclose(f);return 0;
}
static int forge_hex_param(const char *path,const char *key,unsigned char *out,size_t want) {
 char val[8192];size_t z=0;
 return get_forge_param(path,key,val,sizeof val)&&hexdec(val,out,want,&z)&&z==want;
}
static int first_csv_id(const char *path,char *out,size_t cap) {
 FILE *f=fopen(path,"r");if(!f){perror(path);return 0;}
 char line[8192];char *v[MAX_FIELDS];
 if(!fgets(line,sizeof line,f)||!fgets(line,sizeof line,f)){fclose(f);return 0;}
 int n=csv_fields(line,v,MAX_FIELDS);
 if(n<1||strlen(v[0])>=cap){fclose(f);return 0;}
 strcpy(out,v[0]);fclose(f);return 1;
}
static int run_forge_ma(const char *forge_csv,const char *robotA_csv,const char *robotB_csv,
                        const char *server_csv,const char *dataset,const char *map_path) {
 unsigned char c1[65],c2[65],c3[32],c4[65],c5[4096],h_uploaded[32],c6[32],ta[8];
 size_t c5len=0;char ida[256],idb[256],c5hex[8192];
 if(!forge_hex_param(forge_csv,"C1_A_hex",c1,65) ||
    !forge_hex_param(forge_csv,"C2_A",c2,65) ||
    !forge_hex_param(forge_csv,"C3_A_hex",c3,32) ||
    !forge_hex_param(forge_csv,"C4_A",c4,65) ||
    !get_forge_param(forge_csv,"C5_A_hex",c5hex,sizeof c5hex) ||
    !hexdec(c5hex,c5,sizeof c5,&c5len) ||
    !forge_hex_param(forge_csv,"h(ID_a|| s)",h_uploaded,32)) {
   fprintf(stderr,"Forge CSV missing or malformed: expected C1_A_hex, C2_A, C3_A_hex, C4_A, C5_A_hex, and h(ID_a|| s).\n");return 0;
 }
 if(!first_csv_id(robotA_csv,ida,sizeof ida)||!first_csv_id(robotB_csv,idb,sizeof idb)){
   fprintf(stderr,"Cannot read Robot A/B IDs from registration CSVs.\n");return 0;
 }
 /* Only the two requested values are updated: fresh T_A and C6_A.
  * C6 is deliberately calculated with h(ID_a||s) taken from the forge CSV.
  * The server independently derives H* from C3_A XOR x(C2_A'); a mismatch
  * is therefore reported by the unchanged server validation logic. */
 { uint64_t t=(uint64_t)time(NULL);for(int i=7;i>=0;i--){ta[i]=(unsigned char)(t&0xff);t>>=8;} }
 size_t total=32+65+65+32+65+c5len+8,at=0;
 unsigned char *msg=(unsigned char*)malloc(total);if(!msg)return 0;
 memcpy(msg+at,h_uploaded,32);at+=32;memcpy(msg+at,c1,65);at+=65;
 memcpy(msg+at,c2,65);at+=65;memcpy(msg+at,c3,32);at+=32;
 memcpy(msg+at,c4,65);at+=65;memcpy(msg+at,c5,c5len);at+=c5len;
 memcpy(msg+at,ta,8);at+=8;
 int hash_ok=(at==total)&&secr2r_h(msg,total,c6);free(msg);if(!hash_ok)return 0;
 if(mkdir("auth_outputs",0775)!=0&&errno!=EEXIST)return 0;
 if(mkdir("auth_outputs/A",0775)!=0&&errno!=EEXIST)return 0;
 char ma_path[1024];snprintf(ma_path,sizeof ma_path,"auth_outputs/A/M_A.csv");
 FILE *f=fopen(ma_path,"w");if(!f){perror(ma_path);return 0;}
 fprintf(f,"robot_id,peer_robot_id,C1_A_hex,C3_A_hex,C5_A_hex,C6_A_hex,T_A_hex\n%s,%s,",ida,idb);
 const unsigned char *parts[]={c1,c3,c5,c6,ta};size_t lens[]={65,32,c5len,32,8};
 for(int j=0;j<5;j++){if(j)fputc(',',f);for(size_t i=0;i<lens[j];i++)fprintf(f,"%02x",parts[j][i]);}
 fputc('\n',f);if(fclose(f)!=0)return 0;
 if(!save_hex_csv("auth_outputs/A","T_A_refreshed","T_A",ta,8)||
    !save_hex_csv("auth_outputs/A","C6_A_recomputed","C6_A",c6,32))return 0;
 printf("Forge CSV loaded: %s\n",forge_csv);
 printf("Robot A PUF/fuzzy-extractor verification: BYPASSED.\n");
 printf("Only T_A and C6_A were updated; C6_A used h(ID_a||s) from the forge CSV.\n");
 printf("T_A=");for(size_t i=0;i<8;i++)printf("%02x",ta[i]);printf("\nC6_A=");for(size_t i=0;i<32;i++)printf("%02x",c6[i]);printf("\n");
 g_stop_after_c6=1;
 return server_process_ma(ma_path,server_csv,robotA_csv,robotB_csv,dataset,map_path);
}


/* Figure 6: AS receives M_B, verifies Robot B's response, constructs M_2s,
 * and passes it to Robot A. Hash concatenations are fixed-width byte strings. */
static int server_process_mb(const char *mb_path,const char *server_csv,const char *robotA_csv,const char *robotB_csv) {
 char line[16384],*v[MAX_FIELDS],ida[256],idb[256],a_uid[256]="",b_uid[256]=""; unsigned char w1[65],w3[32],w4[65],w5recv[32],tb[8];
 unsigned char s[32],pub[65],bbstored[65],bA[65],c2a[65],w2[65],hids[32],bb[65],v2p[65],w5calc[32];
 unsigned char us[32],y5[32],y6[32],y7[65],y8[32],t2[8],h1[32],h2[32],hc[32],inner[32],buf[512];
 FILE *f=fopen(mb_path,"r");if(!f){perror(mb_path);return 0;}if(!fgets(line,sizeof line,f)||!fgets(line,sizeof line,f)){fclose(f);return 0;}int n=csv_fields(line,v,MAX_FIELDS);size_t z=0;
 if(n<7||strlen(v[0])>=sizeof ida||strlen(v[1])>=sizeof idb||!hexdec(v[2],w1,65,&z)||z!=65||!hexdec(v[3],w3,32,&z)||z!=32||!hexdec(v[4],w4,65,&z)||z!=65||!hexdec(v[5],w5recv,32,&z)||z!=32||!hexdec(v[6],tb,8,&z)||z!=8){fclose(f);fprintf(stderr,"Server: malformed M_B\n");return 0;}strcpy(ida,v[0]);strcpy(idb,v[1]);fclose(f);
 if(!read_hex_param(server_csv,"s_private_scalar",s,32)||!read_hex_param(robotA_csv,"B_public_point",bA,65)||!read_hex_param(robotB_csv,"B_public_point",bbstored,65)||!read_hex_param("auth_outputs/server/C2_A_server.csv","C2_A_prime",c2a,65)){fprintf(stderr,"Server: missing Figure-6 context\n");return 0;}
 {FILE *af=fopen(robotA_csv,"r");if(!af)return 0;if(fgets(line,sizeof line,af)&&fgets(line,sizeof line,af)){n=csv_fields(line,v,MAX_FIELDS);if(n>0&&strlen(v[0])<sizeof a_uid)strcpy(a_uid,v[0]);}fclose(af);}
 {FILE *bf=fopen(robotB_csv,"r");if(!bf)return 0;if(fgets(line,sizeof line,bf)&&fgets(line,sizeof line,bf)){n=csv_fields(line,v,MAX_FIELDS);if(n>0&&strlen(v[0])<sizeof b_uid)strcpy(b_uid,v[0]);}fclose(bf);}
 if(strcmp(ida,b_uid)||strcmp(idb,a_uid)){fprintf(stderr,"Server: M_B sender/recipient ID mismatch\n");return 0;}
 {uint64_t now=(uint64_t)time(NULL),t=0;for(int i=0;i<8;i++)t=(t<<8)|tb[i];if(now<t||now-t>60){fprintf(stderr,"Server: M_B timestamp outside 60-second freshness window\n");return 0;}}
 if(!point_mul_point(s,w1,w2)){fprintf(stderr,"Server: W2B' calculation failed\n");return 0;}
 {unsigned char hw2x[32];if(!secr2r_h(w2+1,32,hw2x))return 0;for(int i=0;i<32;i++)hids[i]=w3[i]^hw2x[i];}
 if(!point_mul_base(hids,bb)||memcmp(bb,bbstored,65)){fprintf(stderr,"Server: B_B' check failed\n");return 0;}
 if(!point_sub(w4,w2,v2p)){fprintf(stderr,"Server: [v2b]P' calculation failed\n");return 0;}
 {size_t at=0;memcpy(buf+at,hids,32);at+=32;{unsigned char mca[97],hca[32];memcpy(mca,c2a+1,32);memcpy(mca+32,bA,65);if(!secr2r_h(mca,sizeof mca,hca))return 0;memcpy(buf+at,hca,32);at+=32;}memcpy(buf+at,w1,65);at+=65;memcpy(buf+at,w2+1,32);at+=32;memcpy(buf+at,v2p,65);at+=65;memcpy(buf+at,tb,8);at+=8;if(!secr2r_h(buf,at,w5calc)||memcmp(w5calc,w5recv,32)){fprintf(stderr,"Server: W5B verification failed\n");return 0;}}
 if(!random_scalar(us)){fprintf(stderr,"Server: u_s generation failed\n");return 0;}
 for(int i=0;i<32;i++)y5[i]=us[i]^c2a[1+i];
 {unsigned char m[162];memcpy(m,w2+1,32);memcpy(m+32,bb,65);if(!secr2r_h(m,97,h1))return 0;memcpy(m,us,32);memcpy(m+32,bb,65);memcpy(m+97,bA,65);if(!secr2r_h(m,sizeof m,h2))return 0;for(int i=0;i<32;i++)y6[i]=h1[i]^h2[i];}
 {unsigned char usp[65];if(!point_mul_base(us,usp)||!point_add(usp,v2p,y7)){fprintf(stderr,"Server: Y7s calculation failed\n");return 0;}}
 {unsigned char m[97];memcpy(m,w2+1,32);memcpy(m+32,bb,65);if(!secr2r_h(m,sizeof m,inner))return 0;size_t at=0;memcpy(buf+at,inner,32);at+=32;memcpy(buf+at,us,32);at+=32;memcpy(m,c2a+1,32);memcpy(m+32,bA,65);if(!secr2r_h(m,sizeof m,hc))return 0;memcpy(buf+at,hc,32);at+=32;memcpy(buf+at,v2p,65);at+=65;uint64_t t=(uint64_t)time(NULL);for(int i=7;i>=0;i--){t2[i]=(unsigned char)(t&255);t>>=8;}memcpy(buf+at,t2,8);at+=8;if(!secr2r_h(buf,at,y8))return 0;}
 if(mkdir("auth_outputs",0775)!=0&&errno!=EEXIST)return 0;if(mkdir("auth_outputs/server",0775)!=0&&errno!=EEXIST)return 0;
 if(!save_hex_csv("auth_outputs/server","Y5s","Y5s",y5,32)||!save_hex_csv("auth_outputs/server","Y6s","Y6s",y6,32)||!save_hex_csv("auth_outputs/server","Y7s","Y7s",y7,65)||!save_hex_csv("auth_outputs/server","Y8s","Y8s",y8,32)||!save_hex_csv("auth_outputs/server","T2s","T2s_unix_seconds_be",t2,8))return 0;
 {char path[1024];snprintf(path,sizeof path,"auth_outputs/server/M_2s.csv");f=fopen(path,"w");if(!f)return 0;fprintf(f,"sender_id,recipient_id,Y5s_hex,Y6s_hex,Y7s_hex,Y8s_hex,T2s_hex\nserver,%s,",idb);const unsigned char *parts[]={y5,y6,y7,y8,t2};size_t lens[]={32,32,65,32,8};for(int j=0;j<5;j++){if(j)fputc(',',f);for(size_t i=0;i<lens[j];i++)fprintf(f,"%02x",parts[j][i]);}fputc('\n',f);if(fclose(f))return 0;}
 printf("Server Figure-6 processing: PASS; M_B freshness, B_B' and W5B checks passed; M_2s generated.\n");return robot_A_process_m2s("auth_outputs/server/M_2s.csv",robotA_csv);
}

static int point_sub(const unsigned char a[65],const unsigned char b[65],unsigned char out[65]) {
 int ok=0; EC_GROUP *g=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); BN_CTX *ctx=BN_CTX_new();
 EC_POINT *pa=g?EC_POINT_new(g):NULL,*pb=g?EC_POINT_new(g):NULL,*neg=g?EC_POINT_new(g):NULL,*res=g?EC_POINT_new(g):NULL;
 if(g&&ctx&&pa&&pb&&neg&&res&&a[0]==4&&b[0]==4&&EC_POINT_oct2point(g,pa,a,65,ctx)==1&&EC_POINT_oct2point(g,pb,b,65,ctx)==1&&EC_POINT_is_on_curve(g,pa,ctx)==1&&EC_POINT_is_on_curve(g,pb,ctx)==1&&EC_POINT_copy(neg,pb)==1&&EC_POINT_invert(g,neg,ctx)==1&&EC_POINT_add(g,res,pa,neg,ctx)==1&&EC_POINT_is_at_infinity(g,res)==0&&EC_POINT_point2oct(g,res,POINT_CONVERSION_UNCOMPRESSED,out,65,ctx)==65)ok=1;
 EC_POINT_free(pa);EC_POINT_free(pb);EC_POINT_free(neg);EC_POINT_free(res);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;
}
static int read_m1s(const char *path,char *ida,size_t acap,char *idb,size_t bcap,unsigned char y1[32],unsigned char y2[32],unsigned char y3[65],unsigned char y4[32],unsigned char t1[8]) {
 FILE*f=fopen(path,"r");if(!f){perror(path);return 0;}char line[16384];int ok=0;if(!fgets(line,sizeof line,f)||!fgets(line,sizeof line,f)){fclose(f);return 0;}char*v[MAX_FIELDS];int n=csv_fields(line,v,MAX_FIELDS);size_t z=0;
 if(n>=7&&strlen(v[0])<acap&&strlen(v[1])<bcap&&hexdec(v[2],y1,32,&z)&&z==32&&hexdec(v[3],y2,32,&z)&&z==32&&hexdec(v[4],y3,65,&z)&&z==65&&hexdec(v[5],y4,32,&z)&&z==32&&hexdec(v[6],t1,8,&z)&&z==8){strcpy(ida,v[0]);strcpy(idb,v[1]);ok=1;}fclose(f);return ok;
}
static int save_scalar_point_csv(const char *dir,const char *name,const char *label,const unsigned char *d,size_t n){return save_hex_csv(dir,name,label,d,n);}
/* Figure 5: Robot B receives M_1s from AS and produces M_B. */
static int robot_B_process_m1s(const char *m1_path,const char *dataset,const char *map_path,const char *server_csv,const char *robotA_csv,const char *robotB_csv) {
 char ida[256],idb[256],uidb[256]; unsigned char y1[32],y2[32],y3[65],y4recv[32],t1[8];
 unsigned char enrolled[510],psi_enroll[16],rho[80]; fe_helper_t helper;
 unsigned char pr[32],xstored[32],dstored[32],s[32],pub[65],psi[16],fpstar[510];
 unsigned char r[32],lc[32],hids[32],bb[65],dcalc[32],ba[65],c2a[65],hca[32],n[32],hn[32],c4[65],y4calc[32];
 unsigned char v1[32],v2[32],w1[65],w2[65],w3[32],v2p[65],v2c4[65],w4[65],w5[32],key[32],tmp[512],buf[512],tb[8],hw2bb[32];
 size_t z=0; unsigned corr[2]={0}; int found=0;
 unsigned long selected_row=0; unsigned selected_hd1=0, selected_hd2=0;
 char outdir[1024]="auth_outputs/robot_B";
 if(!read_m1s(m1_path,ida,sizeof ida,idb,sizeof idb,y1,y2,y3,y4recv,t1)){fprintf(stderr,"Robot B: invalid M1s CSV\n");return 0;}
 if(!load_robot(robotB_csv,uidb,sizeof uidb,enrolled,&helper,psi_enroll,rho)||strcmp(uidb,idb)){fprintf(stderr,"Robot B: registration record/ID mismatch\n");return 0;}
 if(!read_hex_param(robotB_csv,"PR_stored",pr,32)||!read_hex_param(robotB_csv,"X_stored",xstored,32)||!read_hex_param(robotB_csv,"D_stored",dstored,32)||!read_hex_param(server_csv,"s_private_scalar",s,32)||!read_hex_param(server_csv,"Pub_public_point",pub,65)){fprintf(stderr,"Robot B: missing registration parameters\n");return 0;}
 /* Reconstruct a noisy B fingerprint from a genuinely different recorded
  * power-up. Exact duplicate fingerprints are deliberately excluded: a repeated
  * dataset row is not evidence of temporal PUF stability. The enrollment FP,
  * selected-cell map, and candidate FP all use make_fp() and the same bit order. */
 {Cell cells[512];FILE*f=NULL;char*line=NULL;size_t cap=0;ssize_t q;char *head[MAX_FIELDS];int hn,uidcol=-1,datacol=-1;unsigned long row=1;
  if(!read_map(map_path,cells)||(f=fopen(dataset,"r"))==NULL){fprintf(stderr,"Robot B: cannot open PUF inputs\n");if(f)fclose(f);return 0;}
  if((q=getline(&line,&cap,f))<0){free(line);fclose(f);return 0;}hn=csv_fields(line,head,MAX_FIELDS);for(int i=0;i<hn;i++){if(!strcmp(head[i],"uid"))uidcol=i;if(!strcmp(head[i],"data"))datacol=i;}
  if(uidcol<0||datacol<0){free(line);fclose(f);return 0;}
  unsigned best_sum=UINT32_MAX,best_d1=0,best_d2=0; unsigned long best_row=0;
  while((q=getline(&line,&cap,f))>=0){row++;char *v[MAX_FIELDS];int nf=csv_fields(line,v,MAX_FIELDS);if(nf<=uidcol||nf<=datacol||strcmp(v[uidcol],uidb))continue;unsigned char raw[512],cand[510],ps[16];unsigned co[2];if(!parse_data(v[datacol],raw)||!make_fp(raw,cells,cand))continue;
  /* Do not accept a byte-for-byte identical fingerprint as an alternate readout. */
  if(memcmp(cand,enrolled,510)==0)continue;
  unsigned d1=hd(cand,enrolled,255),d2=hd(cand+255,enrolled+255,255);if(d1+d2<best_sum){best_sum=d1+d2;best_d1=d1;best_d2=d2;best_row=row;}if(d1>15||d2>15)continue;if(!fe_rep(cand,&helper,ps,co)||memcmp(ps,psi_enroll,16))continue;memcpy(fpstar,cand,510);memcpy(psi,ps,16);corr[0]=co[0];corr[1]=co[1];
   selected_row=row;selected_hd1=d1;selected_hd2=d2;found=1;
   best_row=row;best_d1=d1;best_d2=d2;break;}
  free(line);fclose(f);
  if(!found) fprintf(stderr,"Robot B: scanned same-UID rows; closest alternate was row %lu with block HD=(%u,%u), sum=%u (BCH limit is 15 per block).\n",best_row,best_d1,best_d2,best_sum);
 }
 if(!found){fprintf(stderr,"Robot B: no valid alternate PUF readout reconstructed; no threshold was relaxed.\n");return 0;}
 printf("Robot B selected alternate readout at dataset row %lu; block HD=(%u,%u); corrected=(%u,%u).\n",
        selected_row,selected_hd1,selected_hd2,corr[0],corr[1]);
 if(mkdir("auth_outputs",0775)!=0&&errno!=EEXIST)return 0;
 if(mkdir(outdir,0775)!=0&&errno!=EEXIST)return 0;
 {FILE *pf=fopen("auth_outputs/robot_B/FPstar_B.csv","w");if(!pf){perror("auth_outputs/robot_B/FPstar_B.csv");return 0;}fprintf(pf,"robot_id,dataset_row,fpstar_bits,block1_hd,block2_hd,corrected_block1,corrected_block2\n%s,%lu,",uidb,selected_row);
 for(int i=0;i<510;i++)fputc(fpstar[i]?'1':'0',pf);
 fprintf(pf,",%u,%u,%u,%u\n",selected_hd1,selected_hd2,corr[0],corr[1]);if(fclose(pf))return 0;}
 if(!secr2r_h(psi,16,buf))return 0;for(int i=0;i<32;i++)r[i]=pr[i]^buf[i];memcpy(buf,psi,16);memcpy(buf+16,r,32);if(!secr2r_h(buf,48,lc))return 0;
 for(int i=0;i<32;i++)hids[i]=lc[i]^xstored[i];if(!point_mul_base(hids,bb))return 0;memcpy(buf,bb,65);memcpy(buf+65,lc,32);if(!secr2r_h(buf,97,dcalc))return 0;
 if(memcmp(dcalc,dstored,32)){fprintf(stderr,"Robot B: D_B verification failed\n");return 0;}
 /* Server-side artifacts bind this response to the validated M_A exchange. */
 if(!read_hex_param("auth_outputs/server/B_A_server_check.csv","B_A_prime",ba,65)||!read_hex_param("auth_outputs/server/C2_A_server.csv","C2_A_prime",c2a,65)){fprintf(stderr,"Robot B: missing server exchange context (B_A', C2_A')\n");return 0;}
 memcpy(buf,c2a+1,32);memcpy(buf+32,ba,65);if(!secr2r_h(buf,97,hca))return 0;
 {uint64_t tnow=(uint64_t)time(NULL),ts=0;for(int i=0;i<8;i++)ts=(ts<<8)|t1[i];if(tnow<ts||tnow-ts>60){fprintf(stderr,"Robot B: T1s outside configured 60-second freshness window\n");return 0;}}
 for(int i=0;i<32;i++)n[i]=y1[i]^lc[i];memcpy(buf,n,32);memcpy(buf+32,bb,65);if(!secr2r_h(buf,97,hn))return 0;for(int i=0;i<32;i++)hn[i]^=y2[i];if(memcmp(hn,hca,32)){fprintf(stderr,"Robot B: Y2s relation verification failed\n");return 0;}
 if(!point_mul_base(n,tmp)||!point_sub(y3,tmp,c4)){fprintf(stderr,"Robot B: C4t point subtraction failed\n");return 0;}
 {size_t at=0;memcpy(buf+at,n,32);at+=32;memcpy(buf+at,hca,32);at+=32;memcpy(buf+at,c4,65);at+=65;memcpy(buf+at,t1,8);at+=8;if(!secr2r_h(buf,at,y4calc))return 0;}
 if(memcmp(y4calc,y4recv,32)){fprintf(stderr,"Robot B: Y4s verification failed\n");return 0;}
 if(!random_scalar(v1)||!random_scalar(v2)||!point_mul_base(v1,w1)||!point_mul_point(v1,pub,w2)||!point_mul_base(v2,v2p)||!point_add(w2,v2p,w4)||!point_mul_point(v2,c4,v2c4)){fprintf(stderr,"Robot B: W point generation failed\n");return 0;}
 {unsigned char hw2x[32];if(!secr2r_h(w2+1,32,hw2x))return 0;for(int i=0;i<32;i++)w3[i]=hids[i]^hw2x[i];}
 {uint64_t t=(uint64_t)time(NULL);for(int i=7;i>=0;i--){tb[i]=(unsigned char)(t&255);t>>=8;}size_t at=0;memcpy(buf+at,hids,32);at+=32;memcpy(buf+at,hca,32);at+=32;memcpy(buf+at,w1,65);at+=65;memcpy(buf+at,w2+1,32);at+=32;memcpy(buf+at,v2p,65);at+=65;memcpy(buf+at,tb,8);at+=8;if(!secr2r_h(buf,at,w5))return 0;}
 {memcpy(buf,w2+1,32);memcpy(buf+32,bb,65);if(!secr2r_h(buf,97,hw2bb))return 0;memcpy(buf, hca,32);memcpy(buf+32,hw2bb,32);memcpy(buf+64,v2c4,65);if(!secr2r_h(buf,129,key))return 0;}
 if(mkdir("auth_outputs",0775)!=0&&errno!=EEXIST)return 0;if(mkdir(outdir,0775)!=0&&errno!=EEXIST)return 0;
 if(!save_hex_csv(outdir,"Psi_B_star","Psi_B_star",psi,16)||!save_hex_csv(outdir,"r_B_star","r_B_star",r,32)||!save_hex_csv(outdir,"LC_B_star","LC_B_star",lc,32)||!save_hex_csv(outdir,"H_B_star","H_ID_s_B_star",hids,32)||!save_hex_csv(outdir,"B_B_star","B_B_star",bb,65)||!save_hex_csv(outdir,"D_B_check","D_B_check",dcalc,32)||!save_hex_csv(outdir,"n_B_star","n_B_star",n,32)||!save_hex_csv(outdir,"C4_B_star","C4_B_star",c4,65)||!save_hex_csv(outdir,"Y4_B_check","Y4_B_check",y4calc,32)||!save_hex_csv(outdir,"v1_B_private","v1_B_private",v1,32)||!save_hex_csv(outdir,"v2_B_private","v2_B_private",v2,32)||!save_hex_csv(outdir,"W1_B","W1_B",w1,65)||!save_hex_csv(outdir,"W2_B","W2_B",w2,65)||!save_hex_csv(outdir,"W3_B","W3_B",w3,32)||!save_hex_csv(outdir,"W4_B","W4_B",w4,65)||!save_hex_csv(outdir,"W5_B","W5_B",w5,32)||!save_hex_csv(outdir,"SessionKey_B","SK_B",key,32)||!save_hex_csv(outdir,"T_B","T_B_unix_seconds_be",tb,8))return 0;
 {char path[1024];snprintf(path,sizeof path,"%s/M_B.csv",outdir);FILE*f=fopen(path,"w");if(!f)return 0;fprintf(f,"sender_id,recipient_id,W1_B_hex,W3_B_hex,W4_B_hex,W5_B_hex,T_B_hex\n%s,%s,",idb,ida);const unsigned char*parts[]={w1,w3,w4,w5,tb};size_t lens[]={65,32,65,32,8};for(int j=0;j<5;j++){if(j)fputc(',',f);for(size_t i=0;i<lens[j];i++)fprintf(f,"%02x",parts[j][i]);}fputc('\n',f);if(fclose(f))return 0;}
 if(!save_hex_csv(".","sessionkey","SK_B",key,32)){fprintf(stderr,"Robot B: could not write sessionkey.csv\n");return 0;}
 printf("Robot B Figure-5 processing: PASS; PUF, D_B, Y2s and Y4s checks passed. sessionkey.csv written.\n");
 if(!server_process_mb("auth_outputs/robot_B/M_B.csv",server_csv,robotA_csv,robotB_csv)){fprintf(stderr,"Server/Robot A Figure-6 phase failed.\n");return 0;}
 (void)fpstar;(void)corr;return 1;
}

static int generate_message_a(const char *uid,const char *robotA,const char *robotB,const char *server,const char *dataset,const char *map_path,
 const unsigned char psi[16],const unsigned char rho[80],const unsigned char fpstar[510],
 unsigned long dataset_row,unsigned hd1,unsigned hd2,unsigned corr1,unsigned corr2) {
 unsigned char pr[32],xstored[32],dstored[32],bA_stored[65],bB[65],pub[65],s[32];
 unsigned char hpsi[32],rstar[32],lc[32],hval[32],bA[65],dcalc[32];
 unsigned char k1[32],k2[32],c1[65],c2[65],c3[32],c4[65],c5[4096],c6[32],payload[162],ta[8];
 size_t c5len=0; unsigned char *tmp=NULL; size_t tmplen=0; char outdir[1024]="auth_outputs/A";
 (void)fpstar; (void)dataset_row; (void)hd1; (void)hd2; (void)corr1; (void)corr2; (void)rho;
 if(!read_hex_param(robotA,"PR_stored",pr,32)||!read_hex_param(robotA,"X_stored",xstored,32)||!read_hex_param(robotA,"D_stored",dstored,32)||!read_hex_param(robotA,"B_public_point",bA_stored,65)||!read_hex_param(robotB,"B_public_point",bB,65)||!read_hex_param(server,"Pub_public_point",pub,65)||!read_hex_param(server,"s_private_scalar",s,32)) {fprintf(stderr,"Missing/invalid registration parameters for A, B, or server.\n");return 0;}
 if(!secr2r_h(psi,16,hpsi))return 0;
 for(size_t i=0;i<32;i++)rstar[i]=pr[i]^hpsi[i];
 tmp=malloc(16+32); if(!tmp)return 0; memcpy(tmp,psi,16);memcpy(tmp+16,rstar,32);
 if(!secr2r_h(tmp,48,lc)){free(tmp);return 0;} free(tmp);tmp=NULL;
 for(size_t i=0;i<32;i++)hval[i]=lc[i]^xstored[i];
 if(!point_mul_base(hval,bA)){fprintf(stderr,"Could not compute B_A* from H*.\n");return 0;}
 tmp=malloc(65+32);if(!tmp)return 0;memcpy(tmp,bA,65);memcpy(tmp+65,lc,32);
 if(!secr2r_h(tmp,97,dcalc)){free(tmp);return 0;}free(tmp);tmp=NULL;
 if(memcmp(dcalc,dstored,32)){fprintf(stderr,"Robot A registration check D_A* failed; aborting.\n");return 0;}
 if(!random_scalar(k1)||!random_scalar(k2)||!point_mul_base(k1,c1)||!point_mul_point(k1,pub,c2)||!point_mul_base(k2,c4)){fprintf(stderr,"ECC random/scalar multiplication failed.\n");return 0;}
 /* C3 = H* XOR x-coordinate(C2), both fixed-width 32-byte values. */
 for(size_t i=0;i<32;i++)c3[i]=hval[i]^c2[1+i];
 /* C5 = ENC_Pub(B_B || y-coordinate(C2) || C4). */
 memcpy(payload,bB,65);memcpy(payload+65,c2+33,32);memcpy(payload+97,c4,65);
 if(!secr2r_enc_c5_payload(pub,payload,sizeof payload,c5,sizeof c5,&c5len)){fprintf(stderr,"C5 encryption failed.\n");return 0;}
 /* Timestamp encoding assumption: Unix seconds, unsigned 64-bit big-endian. */
 { uint64_t t=(uint64_t)time(NULL); for(int i=7;i>=0;i--){ta[i]=(unsigned char)(t&0xff);t>>=8;} }
 tmplen=32+65+65+32+65+c5len+8; tmp=malloc(tmplen);if(!tmp)return 0;size_t at=0;
 memcpy(tmp+at,hval,32);at+=32;memcpy(tmp+at,c1,65);at+=65;memcpy(tmp+at,c2,65);at+=65;memcpy(tmp+at,c3,32);at+=32;memcpy(tmp+at,c4,65);at+=65;memcpy(tmp+at,c5,c5len);at+=c5len;memcpy(tmp+at,ta,8);at+=8;
 if(at!=tmplen||!secr2r_h(tmp,tmplen,c6)){free(tmp);return 0;}free(tmp);
 if(mkdir("auth_outputs",0775)!=0&&errno!=EEXIST){perror("auth_outputs");return 0;}
 if(mkdir(outdir,0775)!=0&&errno!=EEXIST){perror(outdir);return 0;}
 if(!save_hex_csv(outdir,"Psi_A_star","Psi_A_star",psi,16)||!save_hex_csv(outdir,"rho_seed_A","rho_seed_A",rho,80)||
 !save_hex_csv(outdir,"r_A_star","r_A_star",rstar,32)||!save_hex_csv(outdir,"LC_A_star","LC_A_star",lc,32)||
 !save_hex_csv(outdir,"H_A_star","H_A_star",hval,32)||!save_hex_csv(outdir,"B_A_star","B_A_star",bA,65)||
 !save_hex_csv(outdir,"D_A_check","D_A_check",dcalc,32)||!save_hex_csv(outdir,"k1_A_private","k1_A_private",k1,32)||
 !save_hex_csv(outdir,"k2_A_private","k2_A_private",k2,32)||!save_hex_csv(outdir,"C1_A","C1_A",c1,65)||
 !save_hex_csv(outdir,"C2_A","C2_A",c2,65)||!save_hex_csv(outdir,"C3_A","C3_A",c3,32)||
 !save_hex_csv(outdir,"C4_A","C4_A",c4,65)||!save_hex_csv(outdir,"C5_A","C5_A",c5,c5len)||
 !save_hex_csv(outdir,"T_A","T_A_unix_seconds_be",ta,8)||!save_hex_csv(outdir,"C6_A","C6_A",c6,32)) return 0;
 /* M_A is one CSV record with every protocol field in hex. */
 { char path[1024];snprintf(path,sizeof path,"%s/M_A.csv",outdir);FILE*f=fopen(path,"w");if(!f){perror(path);return 0;}
 fprintf(f,"robot_id,peer_robot_id,C1_A_hex,C3_A_hex,C5_A_hex,C6_A_hex,T_A_hex\n%s,",uid);
 {char peer[256]="robot_B"; FILE *bf=fopen(robotB,"r"); if(bf){char row[8192]; if(fgets(row,sizeof row,bf)&&fgets(row,sizeof row,bf)){char *bv[MAX_FIELDS];int bn=csv_fields(row,bv,MAX_FIELDS);if(bn>0&&strlen(bv[0])<sizeof peer)strcpy(peer,bv[0]);}fclose(bf);} fprintf(f,"%s,",peer);}
 for(size_t i=0;i<65;i++) fprintf(f,"%02x",c1[i]);
 fputc(',',f);
 for(size_t i=0;i<32;i++) fprintf(f,"%02x",c3[i]);
 fputc(',',f);
 for(size_t i=0;i<c5len;i++) fprintf(f,"%02x",c5[i]);
 fputc(',',f);
 for(size_t i=0;i<32;i++) fprintf(f,"%02x",c6[i]);
 fputc(',',f);
 for(size_t i=0;i<8;i++) fprintf(f,"%02x",ta[i]);
 fputc('\n',f);
 if(fclose(f)!=0)return 0; }
 printf("Robot A Figure-3 parameters generated; D_A check passed. M_A and per-parameter CSV files saved under %s\n",outdir);
 printf("Note: C6 uses SHA-256 over H* || C1 || C2 || C3 || C4 || C5 || T_A; T_A is Unix seconds encoded as 8-byte big-endian.\n");
 (void)s;
 { char ma_path[1024]; if(snprintf(ma_path,sizeof ma_path,"%s/M_A.csv",outdir)>=(int)sizeof ma_path)return 0;
   if(!server_process_ma(ma_path,server,robotA,robotB,dataset,map_path)){fprintf(stderr,"Server rejected M_A.\n");return 0;} }
 return 1;
}

static int robot_A(const char*dataset,const char*map,const char*robotcsv,const char*robotB_csv,const char*server_csv){
 char uid[256]={0};unsigned char enrolled[510],psi_enroll[16],rho[80];fe_helper_t helper;
 if(!load_robot(robotcsv,uid,sizeof uid,enrolled,&helper,psi_enroll,rho)){fprintf(stderr,"Robot A CSV missing FP/Theta/Psi/rho fields\n");return 0;}
 Cell cells[512];if(!read_map(map,cells)){fprintf(stderr,"Cannot load selected-cell map\n");return 0;}
 FILE*f=fopen(dataset,"r");if(!f){perror(dataset);return 0;}char*line=NULL;size_t cap=0;ssize_t z=getline(&line,&cap,f);if(z<0){fclose(f);free(line);return 0;}
 char*head[MAX_FIELDS];int hn=csv_fields(line,head,MAX_FIELDS),uidcol=-1,datacol=-1;
 for(int i=0;i<hn;i++){if(!strcmp(head[i],"uid"))uidcol=i;if(!strcmp(head[i],"data"))datacol=i;}
 if(uidcol<0||datacol<0){fprintf(stderr,"Dataset must have uid and data columns\n");fclose(f);free(line);return 0;}
 unsigned long rowno=1;int found=0;unsigned char fpstar[510],psistar[16];unsigned corr[2]={0};
 while((z=getline(&line,&cap,f))>=0){rowno++;char *v[MAX_FIELDS];int n=csv_fields(line,v,MAX_FIELDS);if(n<=uidcol||n<=datacol||strcmp(v[uidcol],uid))continue;
  unsigned char raw[512],candidate[510];if(!parse_data(v[datacol],raw)||!make_fp(raw,cells,candidate))continue;
  if(!memcmp(candidate,enrolled,510))continue;
  unsigned d1=hd(candidate,enrolled,255),d2=hd(candidate+255,enrolled+255,255);
  if(d1>15||d2>15)continue; /* BCH(255,139,15): each 255-bit block within t=15 */
  if(!fe_rep(candidate,&helper,psistar,corr))continue;
  memcpy(fpstar,candidate,510);found=1;printf("Robot A selected alternate readout at dataset row %lu; block HD=(%u,%u); corrected=(%u,%u)\n",rowno,d1,d2,corr[0],corr[1]);break;
 }
 fclose(f);free(line);
 if(!found){fprintf(stderr,"No alternate same-UID readout within BCH correction radius found.\n");return 0;}
 if(memcmp(psistar,psi_enroll,16)){fprintf(stderr,"Reconstruction returned a different Psi; FAIL\n");return 0;}
 printf("Robot A PUF reconstruction: PASS; Psi* matches enrolled Psi.\n");
 return generate_message_a(uid, robotcsv, robotB_csv, server_csv, dataset, map, psistar, rho, fpstar, 0, 0, 0, corr[0], corr[1]);
}
int main(int argc,char**argv){
 if(argc>=6 && !strcmp(argv[1],"--forge-ma")) {
   const char *forge=argv[2],*ra=argv[3],*rb=argv[4],*srv=argv[5];
   const char *d=argc>6?argv[6]:"data/crps.csv";
   const char *m=argc>7?argv[7]:"data/selected_cells.csv";
   return run_forge_ma(forge,ra,rb,srv,d,m)?0:1;
 }
 const char*d=argc>1?argv[1]:"data/crps.csv";
 const char*m=argc>2?argv[2]:"data/selected_cells.csv";
 const char*r=argc>3?argv[3]:"auth_inputs/robot_A.csv";
 const char*rb=argc>4?argv[4]:"auth_inputs/robot_B.csv";
 const char*s=argc>5?argv[5]:"auth_inputs/server.csv";
 return robot_A(d,m,r,rb,s)?0:1;
}
