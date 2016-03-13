#ifndef AES_H
#define AES_H

#include <openssl/aes.h>
#include <string.h>
#include "stdint.h"
#include "types.h"

typedef enum{
	AES_SUCCESS = 0,
	AES_UNKNOWN_TYPE,
	AES_UNKNOWN_DIRECTION,
	RSA_MAX = 0x7FFFFFFF
};

#define AES_NORMAL (0x00)
#define AES_CBC    (0x01)
#define AES_ECB    (0x02)

uint32_t __stdcall aes_buffer_size();
uint32_t __stdcall aes_create(AES_KEY *aes, uint32_t type, uint8_t *data, uint32_t data_length);
uint32_t __stdcall aes_crypt(AES_KEY *aes, uint32_t type, uint32_t direction, uint8_t *ivec, uint32_t length, uint8_t *data, uint8_t *buffer);
#endif
