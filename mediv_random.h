#ifndef MEDIV_RANDOM_H
#define MEDIV_RANDOM_H

#include <windows.h>
#include "types.h"
#include "stdint.h"
#include "sha1.h"

typedef struct mediv_random_context{
  uint32_t index;
  uint8_t  data[0x14];
  uint8_t  source1[0x14];
  uint8_t  source2[0x14];
}mediv_random_context;

void __stdcall mediv_random_init(mediv_random_context *ctx, uint8_t *seed, uint32_t length);
void __stdcall mediv_random_get_bytes(mediv_random_context *ctx, uint8_t *buffer, uint32_t length);

#endif