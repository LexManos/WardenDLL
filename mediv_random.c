#include "mediv_random.h"

void mediv_random_update(mediv_random_context *ctx){
  sha1_context sha;
  sha.version = SHA1;
  sha1_reset(&sha);
  sha1_input(&sha, ctx->source1, 0x14);
  sha1_input(&sha, ctx->data,    0x14);
  sha1_input(&sha, ctx->source2, 0x14);
  sha1_digest(&sha, ctx->data);
}

void __stdcall mediv_random_init(mediv_random_context *ctx, uint8_t *seed, uint32_t length){
  uint32_t length1 = length >> 1;
  uint32_t length2 = length - length1;
  sha1_context sha;

  memset(ctx, 0, sizeof(mediv_random_context));  
  
  sha.version = SHA1;
  
  sha1_reset(&sha);
  sha1_input(&sha, seed, length1);
  sha1_digest(&sha, ctx->source1);
  
  sha1_reset(&sha);
  sha1_input(&sha, seed + length1, length2);
  sha1_digest(&sha, ctx->source2);  

  mediv_random_update(ctx);
}
uint8_t mediv_random_get_byte(mediv_random_context *ctx){
  uint32_t value = ctx->data[ctx->index++];
  if(ctx->index >= 0x14){
    mediv_random_update(ctx);
    ctx->index = 0;
  }
  return (uint8_t)(value & 0xFF);
}
void __stdcall mediv_random_get_bytes(mediv_random_context *ctx, uint8_t *buffer, uint32_t length){
  uint32_t x;
  for(x = 0; x < length; x++)
    buffer[x] = mediv_random_get_byte(ctx);
}
