#ifndef ZLIB_EXP_H
#define ZLIB_EXP_H

#include <zlib.h>
#include "stdint.h"

uint32_t __stdcall zlib_deflate_string(uint8_t *data, uint32_t data_len, uint8_t *buffer, uint32_t *buffer_len);
#endif
