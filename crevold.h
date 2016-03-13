#ifndef CREVOLD_H
#define CREVOLD_H

#include <stdlib.h>
#include <string.h>

#include "crev.h"
#include "types.h"
#include "config.h"

uint32_t __stdcall crev_ver1( 
	uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
	uint8_t *ini_file, uint8_t *ini_header, 
	uint32_t *version, uint32_t *checksum, uint8_t *result);

uint32_t __stdcall crev_ver2( 
	uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
	uint8_t *ini_file, uint8_t *ini_header, 
	uint32_t *version, uint32_t *checksum, uint8_t *result);

uint32_t __stdcall crev_old( 
	uint32_t padd, uint8_t archive_ver, uint8_t *seed, 
	uint8_t *ini_file, uint8_t *ini_header, 
	uint32_t *version, uint32_t *checksum, uint8_t *result);

uint32_t crev_get_file_version(uint8_t *file);

#endif