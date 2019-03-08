#ifndef BASE64_C
#define BASE64_C

#include "base64.h"

static const uint8_t base64_encode_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const uint8_t base64_decode_table[256] = {
	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,62,63,62,62,63,
    52,53,54,55,56,57,58,59,60,61, 0, 0, 0, 0, 0, 0,
	 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
	15,16,17,18,19,20,21,22,23,24,25, 0, 0, 0, 0,63,
	 0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
	41,42,43,44,45,46,47,48,49,50,51, 0, 0, 0, 0, 0
};


uint32_t __stdcall base64_decode_size(uint32_t len) {
	return (len + (len % 4)) / 4 * 3;
}

uint32_t __stdcall base64_decode(uint8_t *data, uint32_t data_len, uint8_t *result, uint32_t result_len) {
	uint32_t max = base64_decode_size(data_len);
	uint32_t len = result_len < max ? result_len : max;
	uint32_t idx = 0;
	uint32_t x = 0;

	for (; x < data_len && idx < max; x += 4) {
		uint32_t bits = 
			((                 base64_decode_table[data[x  ]]    ) << 18) |
			((x+1 < data_len ? base64_decode_table[data[x+1]] : 0) << 12) |
			((x+2 < data_len ? base64_decode_table[data[x+2]] : 0) <<  6) |
			((x+3 < data_len ? base64_decode_table[data[x+3]] : 0)      );
		               result[idx++] = (bits >> 16) & 0xFF;
		if (idx < max) result[idx++] = (bits >>  8) & 0xFF;
		if (idx < max) result[idx++] = (bits      ) & 0xFF;
	}
	return idx;
}

uint32_t __stdcall base64_encode_size(uint32_t len) {
	return (len + (len % 3)) / 3 * 4;
}

uint32_t __stdcall base64_encode(uint8_t *data, uint32_t data_len, uint8_t *result, uint32_t result_len) {
	uint32_t max = base64_encode_size(data_len);
	uint32_t len = result_len < max ? result_len : max;
	uint32_t idx = 0;
	uint32_t x = 0;

	for (; x < data_len && idx < max; x += 3) {
		uint32_t bits = 
			((                 data[x  ]    ) << 16) |
			((x+1 < data_len ? data[x+1] : 0) <<  8) |
			((x+2 < data_len ? data[x+2] : 0)      );

		               result[idx++] =                         base64_encode_table[(bits >> 18) & 0x3F];
		if (idx < max) result[idx++] =                         base64_encode_table[(bits >> 12) & 0x3F];
		if (idx < max) result[idx++] = x+1 >= data_len ? '=' : base64_encode_table[(bits >>  6) & 0x3F];
		if (idx < max) result[idx++] = x+2 >= data_len ? '=' : base64_encode_table[(bits      ) & 0x3F];
	}
	return idx;
}

#endif