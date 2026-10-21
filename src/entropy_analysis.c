#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <sys/stat.h>

#define MAX_FIELDS 16
#define MAX_UIDS 256
#define MAX_DATES 32
#define MAX_ADDRS 512
#define PHYSICAL_CELLS 512
#define CRYPTO_CELLS 510
#define TRAIN_WEEKS 4
#define HOLDOUT_WEEKS 5

typedef struct { uint64_t address; int offset; int bit; int cryptographic; } Cell;
static char *uids[MAX_UIDS], *dates[MAX_DATES];
static uint64_t addresses[MAX_ADDRS];
static int nu=0, nd=0, na=0;
static Cell cells[PHYSICAL_CELLS];
static unsigned char *bits = NULL; /* [device][week][selected cell] */
static int *seen_rows = NULL; /* [device][week][address index] */

static void die(const char *m) { fprintf(stderr,"ERROR: %s\n",m); exit(2); }
static char *dupstr(const char *s) { char *p=strdup(s); if(!p) die("out of memory"); return p; }
static int cmpstrp(const void *a,const void *b){ return strcmp(*(char * const*)a,*(char * const*)b); }
static int cmpu64(const void *a,const void *b){ uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b; return x<y?-1:x>y?1:0; }
static int add_string(char **arr,int *n,int cap,const char *s){ for(int i=0;i<*n;i++) if(strcmp(arr[i],s)==0) return i; if(*n>=cap) die("unique-value capacity exceeded"); arr[*n]=dupstr(s); return (*n)++; }
static int add_address(uint64_t a){ for(int i=0;i<na;i++) if(addresses[i]==a) return i; if(na>=MAX_ADDRS) die("address capacity exceeded"); addresses[na]=a; return na++; }
static int idx_str(char **arr,int n,const char *s){ for(int i=0;i<n;i++) if(strcmp(arr[i],s)==0) return i; return -1; }
static int idx_addr(uint64_t a){ for(int i=0;i<na;i++) if(addresses[i]==a) return i; return -1; }

/* CSV parser: handles quoted fields and doubled quote escapes in-place. */
static int csv_parse(char *line,char **out,int cap){
 int n=0; char *r=line,*w=line;
 while(*r && n<cap){
  if(*r=='\n'||*r=='\r') break;
  out[n++]=w;
  if(*r=='"'){
   r++;
   while(*r){ if(*r=='"' && r[1]=='"'){*w++='"';r+=2;continue;} if(*r=='"'){r++;break;} *w++=*r++; }
   while(*r && *r!=','){ if(*r=='\n'||*r=='\r') break; r++; }
   if(*r==','){*w++='\0';r++;} else {*w++='\0';break;}
  } else {
   while(*r && *r!=',' && *r!='\n' && *r!='\r') *w++=*r++;
   if(*r==','){*w++='\0';r++;} else {*w++='\0';break;}
  }
 }
 return n;
}
static uint64_t parse_hex(const char *s){ errno=0; char *e=NULL; unsigned long long v=strtoull(s,&e,16); if(errno||e==s||(*e && *e!=' ')) die("invalid hexadecimal address"); return (uint64_t)v; }
static void load_cells(const char *path){
 FILE *f=fopen(path,"r"); if(!f){perror(path);exit(2);} char *line=NULL; size_t cap=0; ssize_t len=getline(&line,&cap,f); if(len<0)die("empty selected-cell CSV");
 char *v[MAX_FIELDS]; int k=0;
 while((len=getline(&line,&cap,f))>=0){ if(csv_parse(line,v,MAX_FIELDS)<5) die("selected-cell CSV has fewer than five columns"); if(k>=PHYSICAL_CELLS)die("too many selected cells");
  cells[k].address=parse_hex(v[1]); cells[k].offset=atoi(v[2]); cells[k].bit=atoi(v[3]); cells[k].cryptographic=(strcmp(v[4],"True")==0||strcmp(v[4],"true")==0||strcmp(v[4],"1")==0);
  if(cells[k].offset<0||cells[k].offset>=512||cells[k].bit<0||cells[k].bit>7) die("invalid selected-cell coordinate");
  k++;
 }
 fclose(f); free(line); if(k!=PHYSICAL_CELLS)die("expected exactly 512 selected cells");
 for(int i=0;i<CRYPTO_CELLS;i++)if(!cells[i].cryptographic)die("first 510 selected cells must be cryptographic");
}
static void scan_metadata(const char *path){
 FILE *f=fopen(path,"r"); if(!f){perror(path);exit(2);} char *line=NULL;size_t cap=0; char *v[MAX_FIELDS];
 if(getline(&line,&cap,f)<0)die("empty CRPS dataset");
 while(getline(&line,&cap,f)>=0){ int n=csv_parse(line,v,MAX_FIELDS); if(n<6)die("CRPS row has fewer than six fields"); add_string(uids,&nu,MAX_UIDS,v[1]); add_string(dates,&nd,MAX_DATES,v[5]); add_address(parse_hex(v[3])); }
 fclose(f);free(line);
 qsort(uids,nu,sizeof(char*),cmpstrp); qsort(dates,nd,sizeof(char*),cmpstrp); qsort(addresses,na,sizeof(uint64_t),cmpu64);
 if(nu!=84||nd!=9||na!=160) fprintf(stderr,"WARNING: expected 84 devices, 9 dates, 160 addresses; found %d, %d, %d\n",nu,nd,na);
}
static void load_bits(const char *path){
 size_t total=(size_t)nu*nd*PHYSICAL_CELLS; bits=calloc(total,1); if(!bits)die("out of memory allocating bit matrix");
 seen_rows=calloc((size_t)nu*nd*na,sizeof(int)); if(!seen_rows)die("out of memory allocating row map");
 FILE *f=fopen(path,"r"); if(!f){perror(path);exit(2);} char *line=NULL;size_t cap=0;char *v[MAX_FIELDS];getline(&line,&cap,f);
 while(getline(&line,&cap,f)>=0){
  int n=csv_parse(line,v,MAX_FIELDS); if(n<6)die("malformed CRPS row");
  int ui=idx_str(uids,nu,v[1]), di=idx_str(dates,nd,v[5]); uint64_t addr=parse_hex(v[3]); int ai=idx_addr(addr);
  if(ui<0||di<0||ai<0)die("failed to map CRPS row");
  size_t seenidx=((size_t)ui*nd+di)*na+ai; if(seen_rows[seenidx]++)die("duplicate device/date/address row");
  unsigned char raw[512]; char *p=v[4];
  for(int b=0;b<512;b++){ char *e=NULL; long z=strtol(p,&e,10); if(e==p||z<0||z>255)die("invalid raw byte in CRPS data"); raw[b]=(unsigned char)z; p=e; if(b<511){if(*p!=',')die("raw SRAM row must contain 512 comma-separated bytes");p++;} }
  if(*p!='\0')die("raw SRAM row contains more than 512 bytes");
  unsigned char *dst=bits+(((size_t)ui*nd+di)*PHYSICAL_CELLS);
  for(int c=0;c<PHYSICAL_CELLS;c++)if(cells[c].address==addr)dst[c]=(raw[cells[c].offset]>>(7-cells[c].bit))&1;
 }
 fclose(f);free(line);
 for(int i=0;i<nu*nd*na;i++)if(seen_rows[i]!=1)die("dataset has missing device/date/address row");
}
static unsigned char bitat(int u,int d,int c){return bits[(((size_t)u*nd+d)*PHYSICAL_CELLS)+c];}
static double mean_bits_population(int d0,int d1,int c0,int c1){long long ones=0,total=0;for(int u=0;u<nu;u++)for(int d=d0;d<d1;d++)for(int c=c0;c<c1;c++){ones+=bitat(u,d,c);total++;}return total?100.0*ones/total:0;}
static double pairwise_uniqueness(const unsigned char *resp,int ndev,int width){ long double sum=0; long long pairs=0; for(int i=0;i<ndev;i++)for(int j=i+1;j<ndev;j++){int hd=0;for(int c=0;c<width;c++)hd+=(resp[(size_t)i*width+c]!=resp[(size_t)j*width+c]);sum+=100.0*hd/width;pairs++;}return pairs?(double)(sum/pairs):0;}
static void write_summary(const char *out){
 unsigned char *enroll=calloc((size_t)nu*CRYPTO_CELLS,1),*holdfirst=calloc((size_t)nu*CRYPTO_CELLS,1); if(!enroll||!holdfirst)die("out of memory for enrollment");
 for(int u=0;u<nu;u++)for(int c=0;c<CRYPTO_CELLS;c++){int ones=0;for(int d=0;d<TRAIN_WEEKS;d++)ones+=bitat(u,d,c);enroll[(size_t)u*CRYPTO_CELLS+c]=(ones>=2); holdfirst[(size_t)u*CRYPTO_CELLS+c]=bitat(u,TRAIN_WEEKS,c);}
 double train_uni=mean_bits_population(0,TRAIN_WEEKS,0,CRYPTO_CELLS),hold_uni=mean_bits_population(TRAIN_WEEKS,nd,0,CRYPTO_CELLS);
 long long train_hd_sum=0,hold_hd_sum=0;int train_trials=0,hold_trials=0,train_max=0,hold_max=0;
 for(int u=0;u<nu;u++)for(int d=0;d<TRAIN_WEEKS;d++){int hd=0;for(int c=0;c<CRYPTO_CELLS;c++)hd+=bitat(u,d,c)!=enroll[(size_t)u*CRYPTO_CELLS+c];train_hd_sum+=hd;train_trials++;if(hd>train_max)train_max=hd;}
 for(int u=0;u<nu;u++)for(int d=TRAIN_WEEKS;d<nd;d++){int hd=0;for(int c=0;c<CRYPTO_CELLS;c++)hd+=bitat(u,d,c)!=enroll[(size_t)u*CRYPTO_CELLS+c];hold_hd_sum+=hd;hold_trials++;if(hd>hold_max)hold_max=hd;}
 double hmin=0,shannon=0; for(int c=0;c<CRYPTO_CELLS;c++){int ones=0;for(int u=0;u<nu;u++)ones+=enroll[(size_t)u*CRYPTO_CELLS+c];double p1=(double)ones/nu,p0=1-p1,m=fmax(p0,p1);hmin-=log2(m);if(p0>0)shannon-=p0*log2(p0);if(p1>0)shannon-=p1*log2(p1);}
 double helper_leak=232.0,heuristic=fmax(0,hmin-helper_leak),logeps=-1.0+(128.0-heuristic)/2.0;
 FILE *f=fopen(out,"w");if(!f){perror(out);exit(2);} fprintf(f,"metric,value,unit,interpretation\n");
 fprintf(f,"devices,%d,count,unique device IDs\n",nu);fprintf(f,"weekly_readouts,%d,count,chronologically ordered unique timestamps\n",nd);fprintf(f,"regions_per_readout,%d,count,unique SRAM region addresses\n",na);fprintf(f,"physical_selected_cells,512,count,selected physical cells\n");fprintf(f,"cryptographic_cells,510,count,first 510 selected cells used for crypto\n");fprintf(f,"reserved_cells,2,count,last two selected cells reserved\n");fprintf(f,"training_uniformity,%.12f,percent,all device-week training bits\n",train_uni);fprintf(f,"training_uniqueness,%.12f,percent,mean pairwise HD of per-device enrollment responses\n",pairwise_uniqueness(enroll,nu,CRYPTO_CELLS));fprintf(f,"training_BER,%.12f,percent,mean per-device per-week Hamming distance from enrollment\n",100.0*train_hd_sum/(train_trials*CRYPTO_CELLS));fprintf(f,"training_max_HD,%d,bits,maximum per device-week training HD\n",train_max);fprintf(f,"holdout_uniformity,%.12f,percent,all device-week holdout bits\n",hold_uni);fprintf(f,"holdout_uniqueness,%.12f,percent,mean pairwise HD using first holdout week\n",pairwise_uniqueness(holdfirst,nu,CRYPTO_CELLS));fprintf(f,"holdout_BER,%.12f,percent,mean per-device per-week Hamming distance from enrollment\n",100.0*hold_hd_sum/(hold_trials*CRYPTO_CELLS));fprintf(f,"holdout_max_HD,%d,bits,maximum per device-week holdout HD\n",hold_max);fprintf(f,"enrollment_sum_marginal_min_entropy,%.12f,bits,empirical sum of per-cell marginal min-entropy across devices\n",hmin);fprintf(f,"enrollment_sum_marginal_Shannon_entropy,%.12f,bits,empirical sum of per-cell binary Shannon entropies across devices\n",shannon);fprintf(f,"BCH_helper_leakage_accounting,%.0f,bits,2 blocks times 116 redundancy bits; accounting assumption not measured entropy\n",helper_leak);fprintf(f,"heuristic_post_helper_entropy,%.12f,bits,marginal estimate minus leakage accounting; NOT a formal conditional min-entropy bound\n",heuristic);fprintf(f,"LHL_log2_epsilon_using_marginal_estimate,%.12f,log2 epsilon,illustrative only using heuristic post-helper estimate; NOT a security claim because input is not a proven conditional min-entropy bound\n",logeps);
 fclose(f);
 /* per-week summary */
 char path[1024];snprintf(path,sizeof(path),"%s",out);char *dot=strrchr(path,'.');if(dot)strcpy(dot,"_weekly.csv");else strcat(path,"_weekly.csv");f=fopen(path,"w");if(!f){perror(path);exit(2);}fprintf(f,"week,split,uniformity_percent,mean_Hamming_distance_bits,mean_Hamming_distance_percent,max_Hamming_distance_bits,device_week_trials\n");
 for(int d=0;d<nd;d++){long long ones=0,hd_sum=0;int maxhd=0;for(int u=0;u<nu;u++)for(int c=0;c<CRYPTO_CELLS;c++){ones+=bitat(u,d,c);int hd=(bitat(u,d,c)!=enroll[(size_t)u*CRYPTO_CELLS+c]);hd_sum+=hd;}for(int u=0;u<nu;u++){int hd=0;for(int c=0;c<CRYPTO_CELLS;c++)hd+=bitat(u,d,c)!=enroll[(size_t)u*CRYPTO_CELLS+c];if(hd>maxhd)maxhd=hd;}fprintf(f,"%d,%s,%.12f,%.6f,%.12f,%d,%d\n",d+1,d<4?"training":"holdout",100.0*ones/(nu*CRYPTO_CELLS),(double)hd_sum/nu,100.0*hd_sum/(nu*CRYPTO_CELLS),maxhd,nu);}
 fclose(f);
 /* per-cell entropy */
 snprintf(path,sizeof(path),"%s",out);dot=strrchr(path,'.');if(dot)strcpy(dot,"_per_cell_entropy.csv");else strcat(path,"_per_cell_entropy.csv");f=fopen(path,"w");if(!f){perror(path);exit(2);}fprintf(f,"selected_index,cryptographic,p1_enrollment,p0_enrollment,marginal_min_entropy_bits,shannon_entropy_bits\n");for(int c=0;c<CRYPTO_CELLS;c++){int ones=0;for(int u=0;u<nu;u++)ones+=enroll[(size_t)u*CRYPTO_CELLS+c];double p1=(double)ones/nu,p0=1-p1;fprintf(f,"%d,true,%.12f,%.12f,%.12f,%.12f\n",c+1,p1,p0,-log2(fmax(p0,p1)),(p0>0?-p0*log2(p0):0)+(p1>0?-p1*log2(p1):0));}for(int c=CRYPTO_CELLS;c<PHYSICAL_CELLS;c++)fprintf(f,"%d,false,,,,\n",c+1);fclose(f);
 /* device enrollment uniqueness detail */
 snprintf(path,sizeof(path),"%s",out);dot=strrchr(path,'.');if(dot)strcpy(dot,"_device_enrollment.csv");else strcat(path,"_device_enrollment.csv");f=fopen(path,"w");if(!f){perror(path);exit(2);}fprintf(f,"uid,training_enrollment_ones,training_enrollment_uniformity_percent\n");for(int u=0;u<nu;u++){int ones=0;for(int c=0;c<CRYPTO_CELLS;c++)ones+=enroll[(size_t)u*CRYPTO_CELLS+c];fprintf(f,"%s,%d,%.12f\n",uids[u],ones,100.0*ones/CRYPTO_CELLS);}fclose(f);
 printf("C analysis complete: %d devices, %d weekly readouts, %d regions, %d selected cells.\n",nu,nd,na,PHYSICAL_CELLS);printf("Training uniformity: %.6f%% | uniqueness: %.6f%% | BER: %.6f%% | max HD: %d\n",train_uni,pairwise_uniqueness(enroll,nu,CRYPTO_CELLS),100.0*train_hd_sum/(train_trials*CRYPTO_CELLS),train_max);printf("Holdout uniformity: %.6f%% | uniqueness: %.6f%% | BER: %.6f%% | max HD: %d\n",hold_uni,pairwise_uniqueness(holdfirst,nu,CRYPTO_CELLS),100.0*hold_hd_sum/(hold_trials*CRYPTO_CELLS),hold_max);printf("Marginal min-entropy sum: %.6f bits | Shannon sum: %.6f bits\n",hmin,shannon);printf("NOTE: empirical marginal sums are not a formal joint conditional min-entropy bound.\n");free(enroll);free(holdfirst);
}
int main(int argc,char **argv){const char *data=argc>1?argv[1]:"data/crps.csv",*map=argc>2?argv[2]:"data/selected_cells.csv",*out=argc>3?argv[3]:"results/entropy_summary.csv";mkdir("results",0775);load_cells(map);scan_metadata(data);load_bits(data);write_summary(out);return 0;}
