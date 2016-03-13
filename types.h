#ifndef __TYPES_H__
#define __TYPES_H__
//Generic class form Ron that I use in everything, some usefull functions.
#include "stdint.h"

#ifndef TRUE
typedef enum 
{ 
  FALSE, 
  TRUE 
} BOOLEANB;
#else
typedef int BOOLEANB;
#endif

#ifndef MIN
#define MIN(a,b) (a < b ? a : b)
#endif

#ifndef MAX
#define MAX(a,b) (a > b ? a : b)
#endif

#define DIE(a) {fprintf(stderr, "Unrecoverable error in %s(%d): %s\n\n", __FILE__, __LINE__, a); /*abort();*/}
#define DIE_MEM() {DIE("Out of memory.");}

/* Make calls to malloc/realloc that die cleanly if the calls fail. */
void *safe_malloc(uint32_t size);
void *safe_realloc(void *ptr, uint32_t size);

/* Create a UNICODE string based on an ASCII one. Be sure to free the memory! */
char *unicode_alloc(const char *string);
/* Same as unicode_alloc(), except convert the string to uppercase first. */
char *unicode_alloc_upper(const char *string);

#endif

