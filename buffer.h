#ifndef __PACKET_BUFFER_H__
#define __PACKET_BUFFER_H__

#pragma comment (lib, "Ws2_32.lib") 
#include <windows.h>
#include "types.h"

typedef enum
{
	BO_HOST,
	BO_NETWORK,
	BO_LITTLE_ENDIAN,
	BO_BIG_ENDIAN
} BYTE_ORDER_t;

/* This struct shouldn't be accessed directly */
typedef struct 
{
	/* Byte order to use */
	BYTE_ORDER_t byte_order;
	
	/* The current position in the string, used when reading it. */
	uint16_t position;

	/* The maximum length of the buffer that "buffer" is pointing to.  When 
	 * space in this runs out, it's expanded  */
	uint16_t max_length;

	/* The current length of the buffer. */
	uint16_t current_length;

	/* The current buffer.  Will always point to a string of length max_length */
	uint8_t *data;

	/* Set to FALSE when the packet is destroyed, to make sure I don't accidentally
	 * re-use it (again) */
	BOOLEAN valid;

} buffer_t;

/* Create a new packet buffer */
buffer_t *buffer_create(BYTE_ORDER_t byte_order);

/* Create a new packet buffer, with data. */
buffer_t *buffer_create_with_data(BYTE_ORDER_t byte_order, const void *data, const uint16_t length);

/* Destroy the buffer and free resources.  If this isn't used, memory will leak. */
void buffer_destroy(buffer_t *buffer);

/* Get the length of the buffer. */
uint16_t buffer_get_length(buffer_t *buffer);

/* Get the current location in the buffer. */
uint16_t buffer_get_current_offset(buffer_t *buffer);

/* Return the contents of the buffer in a newly allocated string. Fill in the length, if a pointer
 * is given. Note that this allocates memory that has to be freed! */
uint8_t *buffer_create_string(buffer_t *buffer, uint16_t *length);
/* Does the same thing as above, but also frees up the buffer (good for a function return). */
uint8_t *buffer_create_string_and_destroy(buffer_t *buffer, uint16_t *length);

/* Add data to the end of the buffer */
buffer_t *buffer_add_int8(buffer_t *buffer,      const uint8_t data);
buffer_t *buffer_add_int16(buffer_t *buffer,     const uint16_t data);
buffer_t *buffer_add_int32(buffer_t *buffer,     const uint32_t data);
buffer_t *buffer_add_ntstring(buffer_t *buffer,  const char *data);
/* Note: UNICODE support is a hack -- it prints every second character as a NULL, but is otherwise ASCII. */
buffer_t *buffer_add_unicode(buffer_t *buffer,   const char *data);
buffer_t *buffer_add_bytes(buffer_t *buffer,     const void *data, const uint16_t length);
buffer_t *buffer_add_buffer(buffer_t *buffer,    const buffer_t *source);

/* Read the next data from the buffer.  The first read will be at the beginning.
 * An assertion will fail and the program will end if read off
 * the end of the buffer; it's probably a good idea to verify that enough data can be removed
 * before actually attempting to remove it; otherwise, a DoS condition can occur */
uint8_t   buffer_read_next_int8(buffer_t *buffer);
uint16_t  buffer_read_next_int16(buffer_t *buffer);
uint32_t  buffer_read_next_int32(buffer_t *buffer);
char     *buffer_read_next_ntstring(buffer_t *buffer, char *data_ret, uint16_t max_length);
char     *buffer_read_next_unicode(buffer_t *buffer, char *data_ret, uint16_t max_length);
void     *buffer_read_next_bytes(buffer_t *buffer, void *data, uint16_t length);

/* Read the next data, without incrementing the current pointer. */
uint8_t   buffer_peek_next_int8(buffer_t *buffer);
uint16_t  buffer_peek_next_int16(buffer_t *buffer);
uint32_t  buffer_peek_next_int32(buffer_t *buffer);
char     *buffer_peek_next_ntstring(buffer_t *buffer, char *data_ret, uint16_t max_length);
char     *buffer_peek_next_unicode(buffer_t *buffer, char *data_ret, uint16_t max_length);
void     *buffer_peek_next_bytes(buffer_t *buffer, void *data, uint16_t length);

/* Read data at the specified location in the buffer (counting the first byte as 0). */
uint8_t   buffer_read_int8_at(buffer_t *buffer, uint16_t offset);
uint16_t  buffer_read_int16_at(buffer_t *buffer, uint16_t offset);
uint32_t  buffer_read_int32_at(buffer_t *buffer, uint16_t offset);
char     *buffer_read_ntstring_at(buffer_t *buffer, uint16_t offset, char *data_ret, uint16_t max_length);
char     *buffer_read_unicode_at(buffer_t *buffer, uint16_t offset, char *data_ret, uint16_t max_length);
void     *buffer_read_bytes_at(buffer_t *buffer, uint16_t offset, void *data, uint16_t length);

/* These boolean functions check if there are enough bytes left in the buffer to remove
 * specified data.  These should always be used on the server side to verify valid
 * packets */
BOOLEAN buffer_can_read_int8(buffer_t *buffer);
BOOLEAN buffer_can_read_int16(buffer_t *buffer);
BOOLEAN buffer_can_read_int32(buffer_t *buffer);
BOOLEAN buffer_can_read_ntstring(buffer_t *buffer);
BOOLEAN buffer_can_read_unicode(buffer_t *buffer);
BOOLEAN buffer_can_read_bytes(buffer_t *buffer, uint16_t length);

/* These functions check if there are enough bytes in the buffer at the specified location. */
BOOLEAN buffer_can_read_int8_at(buffer_t *buffer, uint16_t offset);
BOOLEAN buffer_can_read_int16_at(buffer_t *buffer, uint16_t offset);
BOOLEAN buffer_can_read_int32_at(buffer_t *buffer, uint16_t offset);
BOOLEAN buffer_can_read_ntstring_at(buffer_t *buffer, uint16_t offset, uint16_t max_length);
BOOLEAN buffer_can_read_unicode_at(buffer_t *buffer, uint16_t offset, uint16_t max_length);
BOOLEAN buffer_can_read_bytes_at(buffer_t *buffer, uint16_t offset, uint16_t length);

/* Print out the buffer in a nice format */
void buffer_print(buffer_t *buffer);
void buffer_print_pad(buffer_t *buffer, uint8_t *padding);

/* Returns a pointer to the actual buffer (I don't recommend using this). */
uint8_t *buffer_get(buffer_t *buffer, uint16_t *length);

#endif
