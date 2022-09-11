#ifndef __SA_TBL_H__
#define __SA_TBL_H__

typedef struct sa_info{
	unsigned int spi;
	unsigned int life_time;
	unsigned int mtu;
	unsigned int seq_no;
	unsigned char valid;
	unsigned char iv_len;
	unsigned char encry_alg;
	unsigned char hash_alg;
	unsigned char cipher_key[32];
	unsigned char hash_key[64];
}SA_TBL;

#define IV_LEN 16
#define CIPHER_KEY_LEN 16
#define HASH_KEY_LEN 32
#define HASH_RESULT_LEN 32



extern void init_sa(void);
extern int add_sa(unsigned int spi, unsigned int lifetime, unsigned int mode, unsigned char encry_alg, char* cipher_key, unsigned int vector1, unsigned char hash_alg, char* hash_key, unsigned int vector2, unsigned int mtu);
extern int update_sa(unsigned int spi, unsigned int lifetime, unsigned int mode, unsigned char encry_alg, char* cipher_key, unsigned int vector1, unsigned char hash_alg, char* hash_key, unsigned int vector2, unsigned int mtu);
extern int query_sa(unsigned int spi, SA_TBL **ipsec_sa);
extern int delete_sa(unsigned int spi);



#endif

