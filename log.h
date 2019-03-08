#ifndef LOG_H
#define LOG_H

#include "stdint.h"
#include "types.h"
#include <windows.h>
#include <stdio.h>

void write_to_file(const uint8_t *data);
uint8_t *to_hex(uint8_t *data, uint32_t size, BOOLEAN spaces);

#endif
