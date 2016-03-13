#include "md5.h"

void md5_process_message_block(md5_context *);

#define md5_batoi(ba, i) \
  ((ba[i+3] << 24) | (ba[i+2] << 16) | (ba[i+1] << 8) | ba[i])

#define md5_rol(word, bits) \
    (((word) << (bits)) | ((word) >> (32-(bits))))


#define md5_itoba(a, ba, i) \
  (ba[i+3] = (uint8_t)(a >> 24)); (ba[i+2] = (uint8_t)(a >> 16)); (ba[i+1] = (uint8_t)(a >> 8)); (ba[i] = (uint8_t)a);

uint32_t md5_math(uint16_t t, uint32_t B, uint32_t C, uint32_t D){
  if(t < 16)      return (D ^ (B & (C ^ D)));
  else if(t < 32) return (C ^ (D & (B ^ C)));
  else if(t < 48) return (B ^ C ^ D);
  else            return (C ^ (B | ~D));
}
uint16_t md5_index(uint16_t t){
  if(t < 16)      return t;
  else if(t < 32) return (5 * t + 1) % 16;
  else if(t < 48) return (3 * t + 5) % 16;
  else            return (7 * t)     % 16;
}
uint16_t md5_shift(uint16_t t){
  if(t < 16)      return (((t % 4) + 1) * 5 + 2);
  else if(t < 32) return (t % 4 == 0 ? 5 : (t % 4 == 1 ?  9 : (t % 4 == 2 ? 14 : 20)));
  else if(t < 48) return (t % 4 == 0 ? 4 : (t % 4 == 1 ? 11 : (t % 4 == 2 ? 16 : 23)));
  else            return (t % 4 == 0 ? 6 : (t % 4 == 1 ? 10 : (t % 4 == 2 ? 15 : 21)));
}

int __stdcall md5_reset(md5_context *ctx){
  uint8_t x = 0;
  
  if(!ctx)
    return md5_null;

  ctx->length_low  = 0;
  ctx->length_high = 0;
  ctx->computed    = 0;
  ctx->corrupted   = 0;
  ctx->message_block_index = 0;

  for(x = 0; x < 64; x++)
    ctx->message_block[x] = 0;
  
  ctx->intermediate_hash[0] = 0x67452301;
  ctx->intermediate_hash[1] = 0xEFCDAB89;
  ctx->intermediate_hash[2] = 0x98BADCFE;
  ctx->intermediate_hash[3] = 0x10325476;

  return md5_success;
}
int __stdcall md5_input(md5_context *ctx, const uint8_t *data, uint32_t length){
  uint32_t x;
  if(!length)
    return md5_success;

  if(!ctx || !data)
    return md5_null;

  if(ctx->computed){
    ctx->corrupted = md5_state_error;
    return md5_state_error;
  }

  for(x = 0; x < length; x++){
    ctx->message_block[ctx->message_block_index++] = (data[x] & 0xFF);
    ctx->length_low += 8;

    if (ctx->length_low == 0){
      ctx->length_high++;
      if(ctx->length_high == 0){
        ctx->corrupted = md5_input_too_long;
        return md5_input_too_long;
      }
    }

    if(ctx->message_block_index == 64)
      md5_process_message_block(ctx);
  }
  return md5_success;
}
int __stdcall md5_digest(md5_context *ctx, uint8_t *digest){
  int i;

  if (!ctx || !digest)
    return md5_null;

  if (ctx->corrupted)
    return ctx->corrupted;

  if (!ctx->computed){
    if (ctx->message_block_index > 55){
      ctx->message_block[ctx->message_block_index++] = 0x80;
  
      while(ctx->message_block_index < 64)
        ctx->message_block[ctx->message_block_index++] = 0;
    
      md5_process_message_block(ctx);
    }else{
      ctx->message_block[ctx->message_block_index++] = 0x80;
    }
  
    while(ctx->message_block_index < 56)
      ctx->message_block[ctx->message_block_index++] = 0;

    md5_itoba(ctx->length_high, ctx->message_block, 60);
    md5_itoba(ctx->length_low,  ctx->message_block, 56);
    
    md5_process_message_block(ctx);
    
    ctx->length_low  = 0;
    ctx->length_high = 0;
    ctx->computed    = 1;
  }

  for(i = 0; i < 4; i++){
    md5_itoba(ctx->intermediate_hash[i], digest, i * 4);
  }

  return md5_success;
}

void md5_process_message_block(md5_context *ctx){
  uint16_t t;          
  uint32_t temp;       
  uint32_t W[16];      
  uint32_t A, B, C, D; 
  const uint32_t K[] = { /* K = floor(abs(sin(x+1) & (2 pow 32))) */
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
  };

  for(t = 0; t < 16; t++)
    W[t] = md5_batoi(ctx->message_block, t * 4);
    
  A = ctx->intermediate_hash[0];
  B = ctx->intermediate_hash[1];
  C = ctx->intermediate_hash[2];
  D = ctx->intermediate_hash[3];

  for(t = 0; t < 64; t++){
    temp = B + md5_rol((A + md5_math(t, B, C, D) + W[md5_index(t)] + K[t]), md5_shift(t));
    A = D; 
    D = C; 
    C = B; 
    B = temp;
  }

  ctx->intermediate_hash[0] += A;
  ctx->intermediate_hash[1] += B;
  ctx->intermediate_hash[2] += C;
  ctx->intermediate_hash[3] += D;

  ctx->message_block_index = 0;
}

int __stdcall md5_verify_data(uint8_t *data, uint32_t length, const uint8_t *correct_md5){
	md5_context ctx;
	uint8_t digest[16];
	uint32_t x;
	md5_reset(&ctx);
	md5_input(&ctx, data, length);
	md5_digest(&ctx, digest);

	if(!correct_md5)
		return 0;

	for(x = 0; x < 16; x++){
		if(digest[x] != correct_md5[x])
			return 0;
	}

	return 1;
}