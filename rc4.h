#ifndef RC4_H
#define RC4_H

#include <string.h>
#include <stdlib.h>
#include <openssl\rc4.h>
#include "stdint.h"
#include "types.h"

void __stdcall rc4_init(struct RC4_KEY *key, uint8_t *base, uint32_t base_length);
void __stdcall rc4_crypt(struct RC4_KEY *key, uint8_t *data, uint32_t length);
void __stdcall rc4_crypt_data(uint8_t *data, uint32_t data_length, uint8_t *base, uint32_t base_length);
uint32_t __stdcall rc4_buffer_size();

//Old functions are MY implmentation of RC4, the others are OpenSSL's version
void __stdcall rc4_init_old(uint8_t *key_buffer, uint8_t *base, uint32_t base_length);
void __stdcall rc4_crypt_old(uint8_t *key, uint8_t *data, uint32_t length);
uint32_t __stdcall rc4_buffer_size_old();

#endif
