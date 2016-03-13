#include "zlib_exp.h"

uint32_t __stdcall zlib_deflate_string(uint8_t *data, uint32_t data_len, uint8_t *buffer, uint32_t *buffer_len){
	uint32_t r;
	z_stream strm;
	
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	
	r = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
	if (r != Z_OK)
		return r;

	strm.avail_in = data_len;
	strm.next_in = data;
	strm.avail_out = *buffer_len;
	strm.next_out = buffer;

	deflate(&strm, Z_FINISH);
	deflateEnd(&strm);

	*buffer_len -= strm.avail_out;
	return 0;
}