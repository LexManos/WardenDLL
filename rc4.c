#ifndef RC4_C
#define RC4_C

#include "rc4.h"

void SWAP(uint8_t *a, uint8_t *b){
  uint8_t t;
  t = *a;
  *a = *b;
  *b = t;
}

void __stdcall rc4_init(struct RC4_KEY *key, uint8_t *base, uint32_t base_length){
	RC4_set_key((RC4_KEY*)key, base_length, base);
}

void __stdcall rc4_crypt(struct RC4_KEY *key, uint8_t *data, uint32_t length){
	uint8_t *out_data = safe_malloc(length);
	RC4((RC4_KEY*)key, length, (const char *)data, out_data);
	memcpy(data, out_data, length);
	free(out_data);
}

uint32_t __stdcall rc4_buffer_size(){
	return sizeof(RC4_KEY);
}

void __stdcall rc4_init_old(uint8_t *key_buffer, uint8_t *base, uint32_t base_length){
  uint8_t val = 0;
  uint32_t position = 0;
  uint32_t i;

  for(i = 0; i < 0x100; i++)
    key_buffer[i] = (uint8_t)i;

  key_buffer[0x100] = 0;
  key_buffer[0x101] = 0;

  for(i = 1; i <= 0x40; i++){
    val += key_buffer[(i * 4) - 4] + base[position++ % base_length];
    SWAP(&key_buffer[(i * 4) - 4], &key_buffer[val & 0x0FF]);

    val += key_buffer[(i * 4) - 3] + base[position++ % base_length];
    SWAP(&key_buffer[(i * 4) - 3], &key_buffer[val & 0x0FF]);

    val += key_buffer[(i * 4) - 2] + base[position++ % base_length];
    SWAP(&key_buffer[(i * 4) - 2], &key_buffer[val & 0x0FF]);

    val += key_buffer[(i * 4) - 1] + base[position++ % base_length];
    SWAP(&key_buffer[(i * 4) - 1], &key_buffer[val & 0x0FF]);
  }
}

void __stdcall rc4_crypt_old(uint8_t *key, uint8_t *data, uint32_t length){
  uint32_t i;
  for(i = 0; i < length; i++){
    key[0x100]++;
    key[0x101] += key[key[0x100]];
    SWAP(&key[key[0x101]], &key[key[0x100]]);
    data[i] ^= key[(key[key[0x101]] + key[key[0x100]]) & 0x0FF];
  }
}
uint32_t __stdcall rc4_buffer_size_old(){
    return 0x102;
}

void __stdcall rc4_crypt_data(uint8_t *data, uint32_t data_length, uint8_t *base, uint32_t base_length){
	RC4_KEY key;
	rc4_init((struct RC4_KEY*)&key, base, base_length);
	rc4_crypt((struct RC4_KEY*)&key, data, data_length);
}

#endif
