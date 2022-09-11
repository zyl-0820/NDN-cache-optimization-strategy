#ifndef _DES_H_
#define _DES_H_

#include "stdint.h"

#define ENCRYPTION_MODE 1
#define DECRYPTION_MODE 0

typedef struct {
	uint8_t k[8];
	uint8_t c[4];
	uint8_t d[4];
} key_set;

void generate_key(uint8_t* key);
void generate_sub_keys(uint8_t* main_key, key_set* key_sets);
void process_message(uint8_t* message_piece, uint8_t* processed_piece, key_set* key_sets, int mode);

#endif