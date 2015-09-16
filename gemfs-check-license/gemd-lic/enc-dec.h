/****************************************************************************************
 * * 库名称：libenc-dec.so
 * * 提供BASE64编码、BASE64解码、RSA签名、RSA验证、SHA256摘要等子函数
 * *
 * * 其中：
 * * 1. enc_string为license提供加密功能：依次进行SHA256摘要、RSA签名、BASE64编码
 * * 2. dec_string提供上述相应的解密功能：依次进行BASE64解码、RSA验证
 * *
 * * 编译方法：gcc -Wall -O2 -fPIC -shared enc-dec.c -o libenc-dec.so -lcrypto -lssl
 * * 其他：返回字符串类型的需在外部使用后释放空间
 * **************************************************************************************/
#ifndef __ENC_DEC_H__
#define __ENC_DEC_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>   
#include <openssl/crypto.h>
 
#define PRIKEY "prikey.pem"
#define PUBKEY "pubkey.pem"
#define BUFFSIZE 4096

unsigned long length;

static const unsigned char map[256] = {  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255,  
255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,  
 52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,  
255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,  
  7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,  
 19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,  
255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  
 37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  
 49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  
255, 255, 255, 255 };

static const char *codes =   
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//BASE64编码
//输入：in：原始字符串  len：原始字符串长度  out：编码后字符串
//输出：加密字符串长度
//int base64_encode(const unsigned char* in,  unsigned long len, unsigned char* out);  

//BASE64解码
//输入：in：原始字符串  len：原始字符串长度  out：解码后字符串
//输出：解密字符串长度
int lic_base64_decode(const unsigned char* in, int len, unsigned char* out);

//RSA签名
//输入：str：原始字符串  prikey_path：私钥文件地址
//输出：签名后字符串
unsigned char* rsa_encode(unsigned char* str, char* prikey_path);

//RSA验证
//输入：str：原始字符串  pubkey_path：公钥文件地址
//输出：验证后字符串
unsigned char* rsa_decode(unsigned char* str, char* pubkey_path);

//SHA256摘要
//输入：orgStr：原始字符串
//输出：摘要后字符串
unsigned char* SHA256_encrypt(char* orgStr);

//license文件字符串加密
//str：原始字符串  prikey：私钥文件地址
//输出：加密后字符串
unsigned char* enc_string(char* str, char*prikey);

//license文件字符串解密
//输入：str：原始字符串  pubkey：公钥文件地址
//输出：解密后字符串
unsigned char* dec_string(const unsigned char* str, char* pubkey);

#endif/*__ENC_DEC_H__*/
