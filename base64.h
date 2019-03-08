#ifndef BASE64_H
#define BASE64_H

#include "stdint.h"
#include "types.h"

uint32_t __stdcall base64_decode_size(uint32_t len);
uint32_t __stdcall base64_decode(uint8_t *data, uint32_t data_len, uint8_t *result, uint32_t result_len);
uint32_t __stdcall base64_encode_size(uint32_t len);
uint32_t __stdcall base64_encode(uint8_t *data, uint32_t data_len, uint8_t *result, uint32_t result_len);

#endif
