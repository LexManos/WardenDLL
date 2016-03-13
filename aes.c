#ifndef AES_C
#define AES_C

#include "aes.h"

uint32_t __stdcall aes_buffer_size(){
	return sizeof(AES_KEY);
}

uint32_t __stdcall aes_create(AES_KEY *aes, uint32_t type, uint8_t *data, uint32_t length){
	switch(type){
		case AES_ENCRYPT: AES_set_encrypt_key(data, length << 3, aes); break;
		case AES_DECRYPT: AES_set_decrypt_key(data, length << 3, aes); break;
		default: return AES_UNKNOWN_TYPE;
	}
	return AES_SUCCESS;
}

uint32_t __stdcall aes_crypt(AES_KEY *aes, uint32_t type, uint32_t direction, uint8_t *ivec, uint32_t length, uint8_t *data, uint8_t *buffer){
	if (direction != AES_ENCRYPT && direction != AES_DECRYPT)
		return AES_UNKNOWN_DIRECTION;

	switch(type){
		case AES_NORMAL:
			if (direction == AES_ENCRYPT)
				AES_encrypt(data, buffer, aes);
			else
				AES_decrypt(data, buffer, aes);
			break;
		case AES_ECB: AES_ecb_encrypt(data, buffer, aes, direction); break;
		case AES_CBC: AES_cbc_encrypt(data, buffer, length, aes, ivec, direction); break;
		default: return AES_UNKNOWN_TYPE;
	}
	return AES_SUCCESS;
}
#endif
