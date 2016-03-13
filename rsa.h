#ifndef RSA_H
#define RSA_H

#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>
#include "stdint.h"
#include "types.h"

typedef enum{
	RSA_SUCCESS = 0,
	RSA_BIO_FAILED,
	RSA_KEY_FAILED,
	RSA_UNKNOWN_TYPE,
	RSA_CRYPT_FAILED,
	RSA_MAX = 0x7FFFFFFF
};

#define RSA_CREATE_EMPTY   (0x00)
#define RSA_PRIVATE        (0x01)
#define RSA_PUBLIC         (0x02)
#define RSA_ENCRYPT        (0x01)

void     __stdcall rsa_free(RSA *rsa);
uint32_t __stdcall rsa_buffer_size();
uint32_t __stdcall rsa_hash_size(RSA *rsa);
uint32_t __stdcall rsa_create(RSA *rsa, uint32_t creation_type, uint8_t *file_data);
uint32_t __stdcall rsa_crypt(RSA *rsa, uint32_t type, uint32_t padding, uint8_t *data, uint32_t data_length, uint8_t *buffer);
#endif
