#ifndef CREVSIMPLE_H
#define CREVSIMPLE_H

#include <stdlib.h>
#include <string.h>

#include "crev.h"
#include "types.h"
#include "config.h"
#include "log.h"
#include "base64.h"
#include "sha1.h"

#pragma comment(lib, "crypt32.lib")

uint32_t __stdcall crev_simple( 
	uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
	uint8_t *ini_file, uint8_t *ini_header, 
	uint32_t *version, uint32_t *checksum, uint8_t *result);

uint32_t __stdcall crev_simple_d1( 
	uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
	uint8_t *ini_file, uint8_t *ini_header, 
	uint32_t *version, uint32_t *checksum, uint8_t *result);

uint32_t __stdcall crev_simple_impl( 
	uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
	uint8_t *ini_file, uint8_t *ini_header, 
	uint32_t *version, uint32_t *checksum, uint8_t *result, BOOLEAN include_cert);

uint32_t __stdcall crev_get_file_public_key(uint8_t *file, uint8_t **key);

#endif