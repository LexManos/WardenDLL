#ifndef CREVLOCKDOWN_H
#define CREVLOCKDOWN_H

#include <stdlib.h>
#include <string.h>

#include "crev.h"
#include "types.h"
#include "config.h"
#include "sha1.h"
#include "pe.h"

typedef struct lockdown_heep{
	uint32_t cur_len;
	uint32_t max_len;
	uint8_t *mem;
} lockdown_heep;

uint32_t __stdcall crev_ver3( 
	uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
	uint8_t *ini_file, uint8_t *ini_header, 
	uint32_t *version, uint32_t *checksum, uint8_t *result);

uint32_t lockdown_shuffle_seed(uint8_t *seed);
void lockdown_word_shifter(uint16_t *word1, uint16_t *word2);
uint32_t lockdown_shuffle_digest(uint8_t *digest, uint8_t *result);

void lockdown_heep_create(lockdown_heep *ctx);
uint32_t lockdown_heep_add(lockdown_heep *ctx, uint8_t *data, uint32_t size);
void lockdown_heep_sort(lockdown_heep *ctx);
void lockdown_heep_cleanup(lockdown_heep *ctx);
uint32_t lockdown_sha1_pad(sha1_context *ctx, uint32_t length);

uint32_t lockdown_proc_reloc(uint32_t pe_file, lockdown_heep *ctx);
uint32_t lockdown_proc_import(uint32_t pe_file, lockdown_heep *ctx);
uint32_t lockdown_hash1(sha1_context *sha, lockdown_heep *ldh, uint32_t section_ptr, uint32_t pe_file, uint32_t seed);
void lockdown_hash2(sha1_context *ctx, uint32_t pe_file, uint32_t *heep_data, uint32_t ptr_memory, uint32_t seed);
#endif