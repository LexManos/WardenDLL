#ifndef TEST_H
#define TEST_H

#pragma comment (lib, "Warden.lib")

#include <string.h>
#include "stdint.h"
#include "types.h"

#include <stdio.h>
#include "crev.h"

void testW2BN();
void printHex(uint8_t *data, int length);
void printHexNull(uint8_t *data, int length);
#endif