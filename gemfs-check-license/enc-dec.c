/*******************************************************************************
 * *   文件名称 : enc-dec.c 
 * *   作    者 : Zhang Shifang
 * *   创建时间 : 2015/08/14
 * *   文件描述 : rsa加密并进行base64编码 && base64解码以及rsa解密
 * *   备    注 : gcc -Wall -O2 -fPIC -shared enc-dec.c -o libenc-dec.so -lcrypto -lssl
 * *   版权声明 : Copyright (C) 2015-2016 湖南安存科技有限公司
 * *   修改历史 : 2015/08/13 1.00 初始版本
 * *******************************************************************************/
#include "enc-dec.h"

/*******************************************************************************
 * * 函数名称  : base64_encode 
 * * 函数描述  : BASE64编码
 * * 输入参数  : in:原始字符串  len:字符串长度  out:编码后字符串
 * * 输出参数  : out
 * * 返回值    : 加密字符的个数
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/08/13    Zhang Shifang   新建
 * *******************************************************************************/
int base64_encode(const unsigned char* in,  unsigned long len,   
                        unsigned char* out)  
{  
	unsigned long i, len2, leven;  
	unsigned char *p;  

	/* valid output size ? */  
	len2 = 4 * ((len + 2) / 3);  
	p = out;  
	leven = 3 * (len / 3);  
	for (i = 0; i < leven; i += 3)
	{  
		*p++ = codes[in[0] >> 2];  
		*p++ = codes[((in[0] & 3) << 4) + (in[1] >> 4)];  
		*p++ = codes[((in[1] & 0xf) << 2) + (in[2] >> 6)];  
		*p++ = codes[in[2] & 0x3f];  
		in += 3;  
	}  

	/* Pad it if necessary...  */  
	if (i < len)
	{  
		unsigned a = in[0];  
		unsigned b = (i+1 < len) ? in[1] : 0;  
		unsigned c = 0;  

		*p++ = codes[a >> 2];  
		*p++ = codes[((a & 3) << 4) + (b >> 4)];  
		*p++ = (i+1 < len) ? codes[((b & 0xf) << 2) + (c >> 6)] : '=';  
		*p++ = '=';  
	}  

	/* append a NULL byte */  
	*p = '\0';  

	return p - out;  
}  


/*******************************************************************************
 * * 函数名称  : base64_decodeBASE64解码 
 * * 函数描述  : BASE64解码
 * * 输入参数  : 原始字符串   out:解码后字符串
 * * 输出参数  : out
 * * 返回值    : 解密字符的个数
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/08/13    Zhang Shifang   新建
 * *******************************************************************************/
int base64_decode(const unsigned char* in, int len, unsigned char* out)  
{  
	unsigned long t, i, y, z;  
	unsigned char c;  
	int g = 3;  

	t = 0;
	z = t;
	y = z;
	i = y;

	for (; in[i] != 0;)
	{  
		if(i >= len)
		{
			printf("the string is too long\n");
			return -1;
		}
		c = map[in[i++]];  
		if (255 == c)
			return -1;  
		if (253 == c)
			continue;  
		if (254 == c)
		{
			c = 0;
			g--;
		}  

		t = (t << 6) | c;  

		if (++y == 4)
		{  
			out[z++] = (unsigned char)((t >> 16) & 255);  
			if(g > 1)
				out[z++] = (unsigned char)((t >> 8) & 255);  
			if(g > 2)
				out[z++] = (unsigned char)(t & 255);  
			t = 0;  
			y = t;
		}  
	}  
	return z;  
}  




 
/*******************************************************************************
 * * 函数名称  : rsa_encode 
 * * 函数描述  : RSA签名
 * * 输入参数  : str:原始字符串  prikey_path:私钥路径
 * * 输出参数  : en:签名后字符串   length:签名后字符串的长度
 * * 返回值    : en:签名后字符串  NULL:failed
 * * 备注      : gcc -Wall -O2 -o xxx xxx.c -lcrypto -lssl
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/08/13    Zhang Shifang   新建
 * *******************************************************************************/
unsigned char* rsa_encode(unsigned char* str, char* prikey_path)
{
	RSA* rsa = NULL;
	FILE* fp = NULL;
	unsigned char* en = NULL;
	int len = 0;
	int rsa_len = 0;

	if ((fp = fopen(prikey_path, "r")) == NULL)
	{
		printf("open private key file failed");
		return NULL;
	}

	/* 读取PEM，PRIKEY格式PEM使用PEM_read_RSA_PRIKEY函数 */
	if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) 
	{
		printf("read private key failed");
		return NULL;
	}

	//RSA_print_fp(stdout, rsa, 0);

	len = strlen((const char*)str);
	rsa_len = RSA_size(rsa);

	en = (unsigned char *)malloc(rsa_len + 1);
	if(NULL == en)
	{
		printf("malloc failed ..\n");
		return NULL;
	}

	memset(en, 0, rsa_len + 1);

	length = RSA_private_encrypt(rsa_len, (unsigned char*)str, (unsigned char*)en, rsa, RSA_NO_PADDING);
	if (length < 0) 
	{
		printf("encrypt failed");
		return NULL;
	}

	RSA_free(rsa);
	fclose(fp);

	return en;
}
  

/*******************************************************************************
 * * 函数名称  : rsa_decode 
 * * 函数描述  : RSA验证
 * * 输入参数  : str:原始字符串  pubkey_path:公钥路径
 * * 输出参数  : string after decode in rsa
 * * 返回值    : de:解密（验证）后的字符串  NULL:failed
 * * 备注      : gcc -Wall -O2 -o xxx xxx.c -lcrypto -lssl
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/08/13    Zhang Shifang   新建
 * *******************************************************************************/
unsigned char* rsa_decode(unsigned char* str, char* pubkey_path)
{
	RSA* rsa = NULL;
	FILE* fp = NULL;
	unsigned char* de = NULL;
	int rsa_len = 0;

	if ((fp = fopen(pubkey_path, "r")) == NULL)
	{
		printf("open public key file failed");
		return NULL;
	}

	if ((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL)
	{
		printf("read public key failed");
		return NULL;
	}

	//RSA_print_fp(stdout, rsa, 0);

	rsa_len = RSA_size(rsa);
	de = (unsigned char*)malloc(rsa_len + 1);
	if(NULL == de)
	{
		printf("malloc failed ..\n");
		return NULL;
	}
	memset(de, 0, rsa_len + 1);

	if (RSA_public_decrypt(rsa_len, (unsigned char*)str, (unsigned char*)de, rsa, RSA_NO_PADDING) < 0)
	{
		printf("decrypt failed");
		return NULL;
	}

	RSA_free(rsa);
	fclose(fp);

	return de;
}
 




/*******************************************************************************
 * * 函数名称  : SHA256_encrypt
 * * 函数描述  : SHA256编码
 * * 输入参数  : src_str:原始字符串
 * * 输出参数  : N/A
 * * 返回值    : 加密后字符串
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/08/11    Zhang Shifang   新建
 * *******************************************************************************/
unsigned char* SHA256_encrypt(char* orgStr)
{
	SHA256_CTX c;  
	unsigned char md[SHA256_DIGEST_LENGTH] = {0};  
	//unsigned char* sha_str = (void*)malloc(2*SHA256_DIGEST_LENGTH);
	static char sha_str[2*SHA256_DIGEST_LENGTH] = {};
	memset(sha_str, 0, 2*SHA256_DIGEST_LENGTH);
	SHA256((unsigned char*)orgStr, strlen(orgStr), md);  
		  
	SHA256_Init(&c);  
	SHA256_Update(&c, orgStr, strlen(orgStr));  
	SHA256_Final(md, &c);  
	OPENSSL_cleanse(&c, sizeof(c));  

	int i = 0;  
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)  
	{ 
		char temp[4] = {0};
		sprintf(temp, "%02x", md[i]);  
		strcat(sha_str,temp);
	}  
		  
	return (unsigned char*)sha_str;
}




/*******************************************************************************
 * * 函数名称  : enc_string
 * * 函数描述  : 依次SHA256、RSA签名、BASE64编码加密字符串
 * * 输入参数  : src_str:原始字符串  prikey:私钥路径
 * * 输出参数  : N/A
 * * 返回值    : string after encrypt
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/08/11    Zhang Shifang   新建
 * *******************************************************************************/
unsigned char* enc_string(char* str, char* prikey)
{
	if(0 != access(prikey, 0))
	{
		printf("\033[1m[Error]the prikey.pem does not exit..\n\033[0m");
		return NULL;
	}

	unsigned char* en_rsa = NULL;
	unsigned char* en_base64 = malloc(4096);
	if(en_base64 == NULL)
	{
		printf("malloc failed ..\n");
		return NULL;
	}

	en_rsa = rsa_encode(SHA256_encrypt(str), prikey);

	if(NULL == en_rsa)
	{
		printf("rsa encode failed");
		free(en_base64);
	}
	if(0 == base64_encode(en_rsa, length, en_base64))
	{
		printf("base64 encode failed");
		free(en_base64);
	}

	free(en_rsa);
	return en_base64;
}


/*******************************************************************************
 * * 函数名称  : dec_string
 * * 函数描述  : 依次BASE64解码、RSA验证字符串
 * * 输入参数  : src_str:原始字符串  pubkey:公钥路径
 * * 输出参数  : N/A
 * * 返回值    : string after dencrypt(still encode in SHA256)
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/08/11    Zhang Shifang   新建
 * *******************************************************************************/
unsigned char* dec_string(const unsigned char* str, char* pubkey)
{
	if(0 != access(pubkey, 0))
	{
		printf("\033[1m[Error]the prikey.pem does not exit..\n\033[0m");
		return NULL;
	}

	unsigned char* de_rsa = NULL;
	unsigned char* de_base64 = NULL;
	de_base64 = malloc(4096);
	if(NULL == de_base64)
	{
		printf("malloc failed ..\n");
		return NULL;
	}

	if(0 == base64_decode(str, 2048, de_base64))
	{
		printf("base64 decode failed");
		free(de_base64);
	}
	de_rsa = rsa_decode((unsigned char*)de_base64, pubkey);
	if(de_rsa == NULL)
	{
		printf("rsa decode failed");
		free(de_base64);
	}
	//printf("%s", de_rsa);

	free(de_base64);
	return de_rsa;
}
