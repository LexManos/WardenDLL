#ifndef MD5_H
#define MD5_H

//This code is based on http://people.csail.mit.edu/rivest/Md5.c 
//Bet heavily edited by me to the point where it isnt recognisable.

#include "stdint.h"
#include "math.h"

#ifndef _MD5_enum_
#define _MD5_enum_
enum{
    md5_success = 0,
    md5_null,            /* Null pointer parameter */
    md5_input_too_long,  /* input data too long, >= 0x10000000000000000*/
    md5_state_error      /* called Input after Digest */
};
#endif
#define md5_hash_size 16

typedef struct md5_context{
  uint32_t      intermediate_hash[md5_hash_size / 4]; /* Message Digest                   */
  uint32_t      length_low;                           /* Message length in bits           */
  uint32_t      length_high;                          /* Message length in bits           */
  int_least16_t message_block_index;                  /* Index into message block array   */
  uint8_t       message_block[64];                    /* 512-bit message blocks           */
  uint8_t       computed;                             /* Is the digest computed?          */
  uint8_t       corrupted;                            /* Is the message digest corrupted? */
} md5_context;

int __stdcall md5_reset(md5_context *);
int __stdcall md5_input(md5_context *, const uint8_t *, uint32_t);
int __stdcall md5_digest(md5_context *, uint8_t *);
int __stdcall md5_verify_data(uint8_t *, uint32_t, const uint8_t *);

#endif
