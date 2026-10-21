/* SecR2R two-robot enrollment (Figure 4 registration equations), P-256.
 * Usage: ./bin/registration [dataset.csv] [selected_cells.csv] [out_dir] [server_secret_hex]
 * Dataset rows are sampled uniformly without replacement, with distinct uid values.
 * The `data` column supplies the 512-byte SRAM readout; selected_cells.csv maps the
 * 510 cryptographic cells. This is desktop replay of recorded SRAM data, not hardware capture.
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "fuzzy_extractor.h"
#include "secr2r_ecc_elgamal.h"
#include "secr2r_hash.h"
#include "secr2r_protocol_crypto.h"
#include "secure_random.h"

#define MAX_FIELDS 16
#define MAX_LINE (1024*16)
#define MAX_ROWS 200000
#define ID_MAX 256
#define FP_BYTES 512
#define OUT_CAP 4096

typedef struct { char *uid; uint8_t fp[FE_INPUT_BITS]; } row_t;
typedef struct { unsigned offset; unsigned bit; int crypto; } cell_t;
typedef struct {
 char uid[ID_MAX]; uint8_t psi[FE_SECRET_BYTES], r[32], pr[32], lc[32], hid[32], x[32], b[65], d[32];
 fe_helper_t helper; uint8_t elc[OUT_CAP]; size_t elc_len;
} robot_t;

static int csv_parse(char *s, char **out, int max) {
 int n=0; char *p=s; while (*p && n<max) { if (*p=='\"') { p++; out[n++]=p; char *w=p; while (*p) { if (*p=='\"') { if (p[1]=='\"') {*w++='\"';p+=2;} else {p++;break;} } else *w++=*p++; } *w='\0'; while (*p && *p!=',')p++; if (*p==',') *p++='\0'; }
 else { out[n++]=p; while (*p && *p!=',')p++; if (*p==',') *p++='\0'; } } return n;
}
static int hex_decode(const char *s,uint8_t *out,size_t n){if(strlen(s)!=2*n)return 0;for(size_t i=0;i<n;i++){unsigned v;if(sscanf(s+2*i,"%2x",&v)!=1)return 0;out[i]=(uint8_t)v;}return 1;}
static void hex_encode(const uint8_t *p,size_t n,char *o){static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){o[2*i]=h[p[i]>>4];o[2*i+1]=h[p[i]&15];}o[2*n]=0;}
static int read_cells(const char *path,cell_t cells[512]) {
 FILE *f=fopen(path,"r"); if(!f){perror(path);return 0;} char *line=NULL;size_t cap=0;ssize_t z=getline(&line,&cap,f);if(z<0){fclose(f);free(line);return 0;} unsigned count=0;
 while((z=getline(&line,&cap,f))>=0){char *v[MAX_FIELDS];int n=csv_parse(line,v,MAX_FIELDS);if(n<5||count>=512)continue;cells[count].offset=(unsigned)strtoul(v[2],NULL,10);cells[count].bit=(unsigned)strtoul(v[3],NULL,10);while(*v[4] && isspace((unsigned char)v[4][strlen(v[4])-1])) v[4][strlen(v[4])-1]=0;cells[count].crypto=(strcmp(v[4],"True")==0||strcmp(v[4],"true")==0||strcmp(v[4],"TRUE")==0||strcmp(v[4],"1")==0);if(cells[count].offset>=512||cells[count].bit>7){fprintf(stderr,"bad cell-map row %u\n",count+2);fclose(f);free(line);return 0;}count++;}
 fclose(f);free(line);if(count!=512){fprintf(stderr,"cell map must have 512 rows; got %u\n",count);return 0;}return 1;
}
static int load_rows(const char *path,const cell_t cells[512],row_t **rows_out,size_t *n_out){
 FILE *f=fopen(path,"r");if(!f){perror(path);return 0;}char *line=NULL;size_t cap=0;ssize_t z=getline(&line,&cap,f);if(z<0){fclose(f);free(line);return 0;}char *header[MAX_FIELDS];int hn=csv_parse(line,header,MAX_FIELDS),uidcol=-1,datacol=-1;for(int i=0;i<hn;i++){if(!strcmp(header[i],"uid"))uidcol=i;if(!strcmp(header[i],"data"))datacol=i;}if(uidcol<0||datacol<0){fprintf(stderr,"dataset must contain uid and data columns\n");fclose(f);free(line);return 0;}
 row_t *rows=calloc(MAX_ROWS,sizeof(*rows));if(!rows){fclose(f);free(line);return 0;}size_t count=0;
 while((z=getline(&line,&cap,f))>=0){char *v[MAX_FIELDS];int n=csv_parse(line,v,MAX_FIELDS);if(n<=uidcol||n<=datacol||!*v[uidcol]||count>=MAX_ROWS)continue;unsigned char raw[FP_BYTES];char *p=v[datacol];int ok=1;for(int i=0;i<FP_BYTES;i++){char *e=NULL;errno=0;long val=strtol(p,&e,10);if(e==p||errno||val<0||val>255){ok=0;break;}raw[i]=(uint8_t)val;p=e;if(i<FP_BYTES-1){if(*p!=','){ok=0;break;}p++;}}if(!ok){fprintf(stderr,"invalid data field at dataset line; expected 512 comma-separated bytes\n");free(rows);fclose(f);free(line);return 0;}
 rows[count].uid=strdup(v[uidcol]);if(!rows[count].uid){free(rows);fclose(f);free(line);return 0;}unsigned k=0;for(unsigned c=0;c<512;c++)if(cells[c].crypto){uint8_t bit=(uint8_t)((raw[cells[c].offset]>>(7u-cells[c].bit))&1u);if(k<FE_INPUT_BITS)rows[count].fp[k++]=bit;}if(k!=FE_INPUT_BITS){fprintf(stderr,"selected map must mark exactly 510 cryptographic cells (found %u)\n",k);free(rows);fclose(f);free(line);return 0;}count++;}
 fclose(f);free(line);if(count<2){fprintf(stderr,"need at least two valid dataset rows\n");free(rows);return 0;}*rows_out=rows;*n_out=count;return 1;
}
static int derive_point(const uint8_t scalar_hash[32],uint8_t point[65]){int ok=0;EC_GROUP *g=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);BN_CTX *ctx=BN_CTX_new();BIGNUM *x=BN_bin2bn(scalar_hash,32,NULL),*order=BN_new();EC_POINT *p=g?EC_POINT_new(g):NULL;if(g&&ctx&&x&&order&&p&&EC_GROUP_get_order(g,order,ctx)==1&&BN_mod(x,x,order,ctx)==1&&!BN_is_zero(x)&&EC_POINT_mul(g,p,x,NULL,NULL,ctx)==1&&EC_POINT_point2oct(g,p,POINT_CONVERSION_UNCOMPRESSED,point,65,ctx)==65)ok=1;EC_POINT_free(p);BN_free(x);BN_free(order);BN_CTX_free(ctx);EC_GROUP_free(g);return ok;}
static int make_hid(const char *uid,const uint8_t s[32],uint8_t out[32]){size_t n=strlen(uid);if(n>SIZE_MAX-32)return 0;uint8_t *buf=malloc(n+32);if(!buf)return 0;memcpy(buf,uid,n);memcpy(buf+n,s,32);int ok=secr2r_h(buf,n+32,out);memset(buf,0,n+32);free(buf);return ok;}
static int enroll_robot(robot_t *r,const row_t *row,const uint8_t s[32],const uint8_t pub[65]){
 memset(r,0,sizeof(*r));if(strlen(row->uid)>=sizeof(r->uid))return 0;strcpy(r->uid,row->uid);
 uint8_t seed[FE_SEED_BITS];for(unsigned i=0;i<FE_SEED_BITS;i++){uint8_t b;if(!secr2r_random_bytes(&b,1))return 0;seed[i]=(uint8_t)(b&1u);}if(!fe_gen(row->fp,seed,&r->helper,r->psi))return 0;
 if(!secr2r_random_bytes(r->r,32))return 0;uint8_t hp[32];if(!secr2r_h(r->psi,FE_SECRET_BYTES,hp))return 0;for(int i=0;i<32;i++)r->pr[i]=r->r[i]^hp[i];uint8_t lcin[48];memcpy(lcin,r->psi,16);memcpy(lcin+16,r->r,32);if(!secr2r_h(lcin,sizeof(lcin),r->lc)||!make_hid(r->uid,s,r->hid))return 0;for(int i=0;i<32;i++)r->x[i]=r->hid[i]^r->lc[i];if(!derive_point(r->hid,r->b))return 0;uint8_t din[97];memcpy(din,r->b,65);memcpy(din+65,r->lc,32);if(!secr2r_h(din,sizeof(din),r->d))return 0;if(!secr2r_enc_lc(pub,r->lc,32,r->elc,sizeof(r->elc),&r->elc_len))return 0;memset(seed,0,sizeof(seed));memset(hp,0,sizeof(hp));return 1;
}
static int write_robot(const char *dir,const robot_t *r){char path[1024];snprintf(path,sizeof(path),"%s/robot_%s.bin",dir,r->uid);FILE *f=fopen(path,"wb");if(!f){perror(path);return 0;}uint8_t helper[FE_HELPER_BYTES];int ok=fe_helper_serialize(&r->helper,helper)&&fwrite("SRR1",1,4,f)==4&&fwrite(r->uid,1,strlen(r->uid)+1,f)==strlen(r->uid)+1&&fwrite(r->pr,1,32,f)==32&&fwrite(helper,1,sizeof(helper),f)==sizeof(helper)&&fwrite(r->x,1,32,f)==32&&fwrite(r->d,1,32,f)==32;fclose(f);return ok;}
static int write_auth_robot_csv(const char *dir,const char *name,const robot_t *r,const row_t *src){
 char path[1024]; if(snprintf(path,sizeof(path),"%s/%s",dir,name)>=(int)sizeof(path))return 0;
 FILE *f=fopen(path,"w"); if(!f){perror(path);return 0;}
 uint8_t helper[FE_HELPER_BYTES]; char hex[FE_HELPER_BYTES*2+1],fp[FE_INPUT_BITS+1],val[OUT_CAP*2+1];
 if(!fe_helper_serialize(&r->helper,helper)){fclose(f);return 0;} hex_encode(helper,sizeof(helper),hex);
 for(unsigned i=0;i<FE_INPUT_BITS;i++)fp[i]=src->fp[i]?'1':'0'; fp[FE_INPUT_BITS]=0;
 fprintf(f,"robot_id,parameter,value\n");
 #define PARAM(k,v) do { fprintf(f,"%s,%s,%s\n",r->uid,(k),(v)); } while(0)
 hex_encode(r->psi,FE_SECRET_BYTES,val); PARAM("Psi_private",val);
 hex_encode(r->r,32,val); PARAM("r_private",val);
 hex_encode(r->lc,32,val); PARAM("LC_private",val);
 hex_encode(r->pr,32,val); PARAM("PR_stored",val);
 PARAM("Theta_helper",hex); PARAM("FP_selected_bits_private",fp);
 hex_encode(r->x,32,val); PARAM("X_stored",val);
 hex_encode(r->d,32,val); PARAM("D_stored",val);
 hex_encode(r->b,65,val); PARAM("B_public_point",val);
 hex_encode(r->elc,r->elc_len,val); PARAM("ELC_ciphertext",val);
 hex_encode(r->helper.toeplitz_seed,FE_SEED_BYTES,val); PARAM("rho_seed",val);
 #undef PARAM
 return fclose(f)==0;
}
static int write_auth_server_csv(const char *dir,const uint8_t s[32],const uint8_t pub[65]){
 char path[1024],sh[65],ph[131]; if(snprintf(path,sizeof(path),"%s/server.csv",dir)>=(int)sizeof(path))return 0;
 FILE *f=fopen(path,"w");if(!f){perror(path);return 0;}hex_encode(s,32,sh);hex_encode(pub,65,ph);
 fprintf(f,"parameter,value\ns_private_scalar,%s\nPub_public_point,%s\ncurve,secp256r1_P-256\nhash,SHA-256\n",sh,ph);
 return fclose(f)==0;
}
int main(int argc,char **argv){const char *dataset=argc>1?argv[1]:"data/crps.csv",*map=argc>2?argv[2]:"data/selected_cells.csv",*outdir=argc>3?argv[3]:"registration_out";uint8_t s[32],pub[65];if(argc>4){if(!hex_decode(argv[4],s,32)){fprintf(stderr,"server secret must be 64 hex characters\n");return 2;}}else{if(!secr2r_random_bytes(s,32)){fprintf(stderr,"CSPRNG failed\n");return 2;}s[0]&=0x7f;if(!(s[31]&1))s[31]|=1;}
 /* Generate the P-256 public key corresponding to s, rejecting invalid scalar values. */
 {EC_GROUP *g=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);BN_CTX *ctx=BN_CTX_new();BIGNUM *bn=BN_bin2bn(s,32,NULL),*ord=BN_new();EC_POINT *q=g?EC_POINT_new(g):NULL;int ok=g&&ctx&&bn&&ord&&q&&EC_GROUP_get_order(g,ord,ctx)==1&&!BN_is_zero(bn)&&BN_cmp(bn,ord)<0&&EC_POINT_mul(g,q,bn,NULL,NULL,ctx)==1&&EC_POINT_point2oct(g,q,POINT_CONVERSION_UNCOMPRESSED,pub,65,ctx)==65;EC_POINT_free(q);BN_free(bn);BN_free(ord);BN_CTX_free(ctx);EC_GROUP_free(g);if(!ok){fprintf(stderr,"invalid server secret scalar; supply valid P-256 scalar hex or rerun\n");return 2;}}
 cell_t cells[512];row_t *rows=NULL;size_t nr=0;if(!read_cells(map,cells)||!load_rows(dataset,cells,&rows,&nr))return 2;
 /* Select two distinct robot UIDs that each have a genuinely different same-UID
  * readout within BCH t=15 in BOTH 255-bit blocks. Identical fingerprints are
  * excluded, and the selected candidates are later checked with fe_rep against
  * the helper data actually generated at enrollment. */
 size_t a=0,b=0,alt_a=0,alt_b=0; int found=0;
 for(size_t i=0;i<nr&&!found;i++){
   size_t ia=nr;
   for(size_t j=0;j<nr;j++) if(i!=j && strcmp(rows[i].uid,rows[j].uid)==0){
     /* A repeated identical fingerprint is not a different power-up readout. */
     if(memcmp(rows[i].fp,rows[j].fp,FE_INPUT_BITS)==0) continue;
     unsigned h1=0,h2=0; for(unsigned k=0;k<255;k++) h1+=(rows[i].fp[k]!=rows[j].fp[k]);
     for(unsigned k=255;k<510;k++) h2+=(rows[i].fp[k]!=rows[j].fp[k]);
     if(h1<=15 && h2<=15){ia=j;break;}
   }
   if(ia==nr) continue;
   for(size_t k=i+1;k<nr&&!found;k++) if(strcmp(rows[i].uid,rows[k].uid)!=0){
     size_t ib=nr;
     for(size_t j=0;j<nr;j++) if(k!=j && strcmp(rows[k].uid,rows[j].uid)==0){
       /* Do not label a duplicate row as a noisy alternate readout. */
       if(memcmp(rows[k].fp,rows[j].fp,FE_INPUT_BITS)==0) continue;
       unsigned h1=0,h2=0; for(unsigned q=0;q<255;q++) h1+=(rows[k].fp[q]!=rows[j].fp[q]);
       for(unsigned q=255;q<510;q++) h2+=(rows[k].fp[q]!=rows[j].fp[q]);
       if(h1<=15 && h2<=15){ib=j;break;}
     }
     if(ib<nr){a=i;alt_a=ia;b=k;alt_b=ib;found=1;}
   }
 }
 if(!found){fprintf(stderr,"no pair of distinct UIDs found with same-UID alternate readouts satisfying HD<=15 in both 255-bit blocks\n");return 4;}
 if(mkdir(outdir,0775)!=0&&errno!=EEXIST){perror(outdir);return 2;}robot_t r1,r2;if(!enroll_robot(&r1,&rows[a],s,pub)||!enroll_robot(&r2,&rows[b],s,pub)){fprintf(stderr,"registration failed during FE or cryptographic operation\n");return 3;}
 /* Independently validate both claimed alternate readouts using the exact
  * helper data generated for the enrolled fingerprint. A Hamming-distance
  * check alone is not sufficient to claim successful fuzzy reconstruction. */
 { uint8_t ps[FE_SECRET_BYTES]; unsigned corrected[2]={0};
   if(!fe_rep(rows[alt_a].fp,&r1.helper,ps,corrected) || memcmp(ps,r1.psi,FE_SECRET_BYTES)!=0){
     fprintf(stderr,"registration validation failed: Robot A alternate row %zu does not reconstruct enrolled Psi\n",alt_a+2);return 4;}
   if(!fe_rep(rows[alt_b].fp,&r2.helper,ps,corrected) || memcmp(ps,r2.psi,FE_SECRET_BYTES)!=0){
     fprintf(stderr,"registration validation failed: Robot B alternate row %zu does not reconstruct enrolled Psi\n",alt_b+2);return 4;}
 }
 if(!write_robot(outdir,&r1)||!write_robot(outdir,&r2) ||
    !write_auth_robot_csv(outdir,"robot_A.csv",&r1,&rows[a]) ||
    !write_auth_robot_csv(outdir,"robot_B.csv",&r2,&rows[b]) ||
    !write_auth_server_csv(outdir,s,pub)) {fprintf(stderr,"failed to write registration/authentication input files\n");return 3;}
 char path[1024];snprintf(path,sizeof(path),"%s/server_registry.csv",outdir);FILE *reg=fopen(path,"w");if(!reg){perror(path);return 3;}fprintf(reg,"uid,B_hex,ELC_hex\n");char bh[131],eh[OUT_CAP*2+1];hex_encode(r1.b,65,bh);hex_encode(r1.elc,r1.elc_len,eh);fprintf(reg,"%s,%s,%s\n",r1.uid,bh,eh);hex_encode(r2.b,65,bh);hex_encode(r2.elc,r2.elc_len,eh);fprintf(reg,"%s,%s,%s\n",r2.uid,bh,eh);fclose(reg);
 /* Explicit research export: plaintext secrets for the requested Excel workbook. Protect this file. */
 snprintf(path,sizeof(path),"%s/private_public_parameters.csv",outdir); FILE *exp=fopen(path,"w");
 if(!exp){perror(path);return 3;}
 char sh[65],ph[131]; hex_encode(s,32,sh); hex_encode(pub,65,ph);
 fprintf(exp,"scope,uid,parameter,hex_or_value\n");
 fprintf(exp,"server,,s_private_scalar,%s\n",sh);
 fprintf(exp,"server,,Pub_public_point,%s\n",ph);
 fprintf(exp,"server,,curve,secp256r1_P-256\nserver,,hash,SHA-256\n");
 robot_t *rr[2]={&r1,&r2}; const row_t *src[2]={&rows[a],&rows[b]};
 for(int j=0;j<2;j++){
   robot_t *q=rr[j]; char tmp[FE_HELPER_BYTES*2+1], fphex[FE_INPUT_BITS+1];
   hex_encode(q->psi,FE_SECRET_BYTES,tmp); fprintf(exp,"robot,%s,Psi_private,%s\n",q->uid,tmp);
   hex_encode(q->r,32,tmp); fprintf(exp,"robot,%s,r_private,%s\n",q->uid,tmp);
   hex_encode(q->lc,32,tmp); fprintf(exp,"robot,%s,LC_private,%s\n",q->uid,tmp);
   hex_encode(q->pr,32,tmp); fprintf(exp,"robot,%s,PR_stored,%s\n",q->uid,tmp);
   uint8_t helper[FE_HELPER_BYTES]; fe_helper_serialize(&q->helper,helper); hex_encode(helper,sizeof(helper),tmp);
   fprintf(exp,"robot,%s,Theta_helper,%s\n",q->uid,tmp);
   hex_encode(q->hid,32,tmp); fprintf(exp,"robot,%s,h_ID_s_private_derived,%s\n",q->uid,tmp);
   hex_encode(q->x,32,tmp); fprintf(exp,"robot,%s,X_stored,%s\n",q->uid,tmp);
   hex_encode(q->b,65,tmp); fprintf(exp,"robot,%s,B_public_point,%s\n",q->uid,tmp);
   hex_encode(q->d,32,tmp); fprintf(exp,"robot,%s,D_stored,%s\n",q->uid,tmp);
   hex_encode(q->elc,q->elc_len,eh); fprintf(exp,"robot,%s,ELC_ciphertext,%s\n",q->uid,eh);
   for(unsigned k=0;k<FE_INPUT_BITS;k++) fphex[k]=src[j]->fp[k]?'1':'0'; fphex[FE_INPUT_BITS]=0;
   fprintf(exp,"robot,%s,FP_selected_bits_private,%s\n",q->uid,fphex);
 }
 fclose(exp);
 snprintf(path,sizeof(path),"%s/registration_summary.txt",outdir);FILE *sum=fopen(path,"w");if(sum){fprintf(sum,"SecR2R P-256 two-robot registration\nRobot A uid: %s (dataset row %zu)\nRobot B uid: %s (dataset row %zu)\nDifferent IDs: %s\nCurve: secp256r1 / P-256\nHash: SHA-256\nPsi length: 128 bits\nPR, LC, X, D lengths: 32 bytes each\nB length: 65-byte uncompressed point\nSerialized fuzzy helper length: %u bytes\nELC ciphertext lengths: %zu, %zu bytes\nRobot files contain PR, fuzzy helper, X, D; server registry contains B and ELC.\n",r1.uid,a+2,r2.uid,b+2,strcmp(r1.uid,r2.uid)?"yes":"NO",(unsigned)FE_HELPER_BYTES,r1.elc_len,r2.elc_len);fclose(sum);}
 snprintf(path,sizeof(path),"%s/selected_fpstar_rows.csv",outdir); FILE *sel=fopen(path,"w"); if(sel){unsigned h1=0,h2=0;for(unsigned q=0;q<255;q++)h1+=(rows[a].fp[q]!=rows[alt_a].fp[q]);for(unsigned q=255;q<510;q++)h2+=(rows[a].fp[q]!=rows[alt_a].fp[q]);fprintf(sel,"robot,uid,enrollment_dataset_line,FPstar_dataset_line,block1_hd,block2_hd\nA,%s,%zu,%zu,%u,%u\n",r1.uid,a+2,alt_a+2,h1,h2);h1=h2=0;for(unsigned q=0;q<255;q++)h1+=(rows[b].fp[q]!=rows[alt_b].fp[q]);for(unsigned q=255;q<510;q++)h2+=(rows[b].fp[q]!=rows[alt_b].fp[q]);fprintf(sel,"B,%s,%zu,%zu,%u,%u\n",r2.uid,b+2,alt_b+2,h1,h2);fclose(sel);}
 printf("PASS: registered two different robot IDs with BCH-valid same-UID alternate readouts: %s and %s\nOutput directory: %s\n",r1.uid,r2.uid,outdir);for(size_t i=0;i<nr;i++)free(rows[i].uid);free(rows);memset(s,0,sizeof(s));return 0;
}
