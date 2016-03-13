#pragma once

#include <windows.h>
#include <stdio.h>
#include "types.h"


uint8_t *read_ini(const uint8_t *file, uint8_t *header, uint8_t *key, uint8_t *defa);
uint32_t read_ini_new(const uint8_t *file, uint8_t *header, uint8_t *key, uint8_t *defa, uint8_t *buff, uint32_t length);
uint32_t write_ini(const uint8_t *file, uint8_t *header, uint8_t *key, uint8_t *data);