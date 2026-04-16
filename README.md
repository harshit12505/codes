// =======================
// Experiment 1
// Classical Ciphers (Caesar + Vigenere)
// =======================
#include <stdio.h>
#include <string.h>
#include <ctype.h>
void caesar_encrypt(char *s, int key){
 for(int i=0; s[i]; i++){
 if(isupper(s[i])) s[i] = ((s[i]-'A')+key)%26 + 'A';
 else if(islower(s[i])) s[i] = ((s[i]-'a')+key)%26 + 'a';
 }
}
void caesar_decrypt(char *s, int key){
 caesar_encrypt(s, 26-key);
}
void vigenere_encrypt(char *pt, char *key){
 int n=strlen(pt), m=strlen(key), j=0;
 for(int i=0;i<n;i++){
 if(isalpha(pt[i])){
 int base = isupper(pt[i])? 'A':'a';
 int k = toupper(key[j%m]) - 'A';
 pt[i] = ((pt[i]-base)+k)%26 + base;
 j++;
 }
 }
}
void vigenere_decrypt(char *ct, char *key){
 int n=strlen(ct), m=strlen(key), j=0;
 for(int i=0;i<n;i++){
 if(isalpha(ct[i])){
 int base = isupper(ct[i])? 'A':'a';
 int k = toupper(key[j%m]) - 'A';
 ct[i] = ((ct[i]-base)-k+26)%26 + base;
 j++;
 }
 }
}
int main(){
 char text1[256] = "Attack at dawn!";
 int key = 3;
 printf("Caesar - Plain: %s\n", text1);
 caesar_encrypt(text1, key);
 printf("Encrypted: %s\n", text1);
 caesar_decrypt(text1, key);
 printf("Decrypted: %s\n\n", text1);
 char text2[256] = "Defend the east wall";
 char keyw[64] = "LEMON";
 printf("Vigenere - Plain: %s\n", text2);
 vigenere_encrypt(text2, keyw);
 printf("Encrypted: %s\n", text2);
 vigenere_decrypt(text2, keyw);
 printf("Decrypted: %s\n", text2);
 return 0;
}
// =======================
// Experiment 2
// Hill Cipher
// =======================
#include <stdio.h>
#include <string.h>
#include <ctype.h>
int mod26(int x){ x%=26; if(x<0) x+=26; return x; }
int det(int a,int b,int c,int d){ return a*d - b*c; }
int inv_mod26(int a){
 a = (a%26+26)%26;
 for(int i=1;i<26;i++) if((a*i)%26==1) return i;
 return -1;
}
void hill_encrypt(char *pt, int K[2][2], char *ct){
 int n=strlen(pt), idx=0;
 for(int i=0;i<n;i+=2){
 int p1 = tolower(pt[i])-'a';
 int p2 = (i+1<n)? tolower(pt[i+1])-'a' : 'x'-'a';
 int c1 = mod26(K[0][0]*p1 + K[0][1]*p2);
 int c2 = mod26(K[1][0]*p1 + K[1][1]*p2);
 ct[idx++]=c1+'a';
 ct[idx++]=c2+'a';
 }
 ct[idx]='\0';
}
void hill_decrypt(char *ct, int K[2][2], char *pt){
 int d = det(K[0][0],K[0][1],K[1][0],K[1][1]);
 int invd = inv_mod26(d);
 if(invd==-1){
 printf("Key matrix not invertible\n");
 return;
 }
 int Kinv[2][2];
 Kinv[0][0] = mod26(invd * K[1][1]);
 Kinv[0][1] = mod26(invd * (-K[0][1]));
 Kinv[1][0] = mod26(invd * (-K[1][0]));
 Kinv[1][1] = mod26(invd * K[0][0]);
 int n=strlen(ct), idx=0;
 for(int i=0;i<n;i+=2){
 int c1 = tolower(ct[i])-'a';
 int c2 = (i+1<n)? tolower(ct[i+1])-'a' : 0;
 int p1 = mod26(Kinv[0][0]*c1 + Kinv[0][1]*c2);
 int p2 = mod26(Kinv[1][0]*c1 + Kinv[1][1]*c2);
 pt[idx++]=p1+'a';
 pt[idx++]=p2+'a';
 }
 pt[idx]='\0';
}
int main(){
 char pt[] = "help";
 int K[2][2] = {{3,3},{2,5}};
 char ct[256], dec[256];
 hill_encrypt(pt,K,ct);
 printf("Plain: %s\nEncrypted: %s\n", pt, ct);
 hill_decrypt(ct,K,dec);
 printf("Decrypted: %s\n", dec);
 return 0;
}
// =======================
// Experiment 3
// RSA Algorithm
// =======================
#include <stdio.h>
long long gcd(long long a,long long b){
 while(b){
 long long t=a%b;
 a=b;
 b=t;
 }
 return a;
}
long long modexp(long long a,long long e,long long mod){
 long long res=1;
 a%=mod;
 while(e){
 if(e&1) res=(res*a)%mod;
 a=(a*a)%mod;
 e>>=1;
 }
 return res;
}
long long invmod(long long a,long long m){
 long long m0=m,x0=0,x1=1;
 while(a>1){
 long long q=a/m;
 long long t=m;
 m=a%m;
 a=t;
 t=x0;
 x0=x1-q*x0;
 x1=t;
 }
 if(x1<0) x1+=m0;
 return x1;
}
int main(){
 long long p=61,q=53;
 long long n=p*q;
 long long phi=(p-1)*(q-1);
 long long e=17;
 long long d=invmod(e,phi);
 long long m=65;
 long long c=modexp(m,e,n);
 long long dec=modexp(c,d,n);
 printf("Plain: %lld\nCipher: %lld\nDecrypted: %lld\n",m,c,dec);
 return 0;
}
// =======================
// Experiment 4
// Diffie-Hellman
// =======================
#include <stdio.h>
long long modexp(long long a,long long e,long long mod){
 long long res=1;
 a%=mod;
 while(e){
 if(e&1) res=(res*a)%mod;
 a=(a*a)%mod;
 e>>=1;
 }
 return res;
}
int main(){
 long long p=23,g=5;
 long long a=6,b=15;
 long long A=modexp(g,a,p);
 long long B=modexp(g,b,p);
 long long s1=modexp(B,a,p);
 long long s2=modexp(A,b,p);
 printf("Shared: %lld %lld\n",s1,s2);
 return 0;
}
// =======================
// Experiment 5
// DES (Toy Feistel)
// =======================
#include <stdio.h>
#include <stdint.h>
uint8_t F(uint8_t r,uint8_t k){
 return ((r^k)+((r&k)<<1))&0xFF;
}
uint16_t feistel_encrypt(uint16_t block,uint8_t keys[],int rounds){
 uint8_t L=(block>>8)&0xFF;
 uint8_t R=block&0xFF;
 for(int i=0;i<rounds;i++){
 uint8_t newL=R;
 uint8_t newR=L^F(R,keys[i]);
 L=newL;
 R=newR;
 }
 return (L<<8)|R;
}
uint16_t feistel_decrypt(uint16_t block,uint8_t keys[],int rounds){
 uint8_t L=(block>>8)&0xFF;
 uint8_t R=block&0xFF;
 for(int i=rounds-1;i>=0;i--){
 uint8_t newR=L;
 uint8_t newL=R^F(L,keys[i]);
 L=newL;
 R=newR;
 }
 return (L<<8)|R;
}
int main(){
 uint16_t plain=0x1234;
 uint8_t keys[4]={0x0F,0x1A,0x2B,0x3C};
 uint16_t cipher=feistel_encrypt(plain,keys,4);
 uint16_t dec=feistel_decrypt(cipher,keys,4);
 printf("%04X %04X %04X\n",plain,cipher,dec);
 return 0;
}
// =======================
// Experiment 6
// AES (Demo)
// =======================
#include <stdio.h>
#include <stdint.h>
void addRoundKey(uint8_t state[16],uint8_t key[16]){
 for(int i=0;i<16;i++) state[i]^=key[i];
}
void subBytes_demo(uint8_t state[16]){
 for(int i=0;i<16;i++) state[i]=(state[i]*3+1)&0xFF;
}
int main(){
 uint8_t state[16];
 uint8_t key[16]={0};
 for(int i=0;i<16;i++) state[i]=i;
 addRoundKey(state,key);
 subBytes_demo(state);
 for(int i=0;i<16;i++) printf("%02X ",state[i]);
 return 0;
}
// =======================
// Experiment 7
// HMAC (Demo)
// =======================
#include <stdio.h>
#include <string.h>
void simple_hash(unsigned char *data,int len,unsigned char out[32]){
 unsigned char s=0;
 for(int i=0;i<len;i++) s+=data[i];
 for(int i=0;i<32;i++) out[i]=s;
}
void hmac_demo(unsigned char *key,int klen,unsigned char *msg,int
mlen,unsigned char out[32]){
 unsigned char block[64]={0},ik[64],ok[64];
 memcpy(block,key,klen);
 for(int i=0;i<64;i++){
 ik[i]=block[i]^0x36;
 ok[i]=block[i]^0x5c;
 }
 unsigned char inner[1024];
 memcpy(inner,ik,64);
 memcpy(inner+64,msg,mlen);
 unsigned char ih[32];
 simple_hash(inner,64+mlen,ih);
 unsigned char outer[96];
 memcpy(outer,ok,64);
 memcpy(outer+64,ih,32);
 simple_hash(outer,96,out);
}
int main(){
 unsigned char key[]="secret";
 unsigned char msg[]="hello";
 unsigned char mac[32];
 hmac_demo(key,strlen((char*)key),msg,strlen((char*)msg),mac);
 printf("%02X\n",mac[0]);
 return 0;
}
// =======================
// Experiment 8
// Digital Signature (RSA)
// =======================
#include <stdio.h>
#include <string.h>
long long modexp(long long a,long long e,long long mod){
 long long res=1;
 a%=mod;
 while(e){
 if(e&1) res=(res*a)%mod;
 a=(a*a)%mod;
 e>>=1;
 }
 return res;
}
long long simple_hash(char *m){
 long long s=0;
 for(int i=0;i<strlen(m);i++)
 s=(s*31+m[i])%1000;
 return s;
}
int main(){
 long long p=61,q=53;
 long long n=p*q;
 long long e=17,d=2753;
 char msg[]="Test";
 long long h=simple_hash(msg);
 long long sig=modexp(h,d,n);
 long long verify=modexp(sig,e,n);
 printf("%lld %lld %lld\n",h,sig,verify);
 return 0;
}
// =======================
// Experiment 9
// Hash (OpenSSL)
// =======================
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
void print_digest(unsigned char *d,unsigned int n){
 for(int i=0;i<n;i++) printf("%02x",d[i]);
 printf("\n");
}
int main(){
 const char *msg="hello";
 unsigned char md[EVP_MAX_MD_SIZE];
 unsigned int len;
 EVP_Digest(msg,strlen(msg),md,&len,EVP_md5(),NULL);
 print_digest(md,len);
 EVP_Digest(msg,strlen(msg),md,&len,EVP_sha1(),NULL);
 print_digest(md,len);
 EVP_Digest(msg,strlen(msg),md,&len,EVP_sha256(),NULL);
 print_digest(md,len);
 return 0;
}
