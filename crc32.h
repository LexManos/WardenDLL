#ifndef CRC32_H
#define CRC32_H

#include "stdint.h"
#include "types.h"

uint32_t __stdcall crc32_seed();
uint32_t __stdcall crc32_calc(uint8_t *table, uint32_t seed, uint8_t *data, uint32_t len);
uint32_t __stdcall crc32b_calc(uint8_t *table, uint32_t seed, uint8_t *data, uint32_t len);
uint32_t __stdcall crc32_create(uint32_t polynomial, uint8_t *buffer);
uint32_t __stdcall crc32_finish(uint32_t crc);
uint32_t __stdcall crc32_buffer_size();

#endif
