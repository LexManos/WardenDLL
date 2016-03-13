/* types.c
 * By Ron
 * Created September 1, 2008
 *
 * See LICENSE.txt
 *
 * Functions for converting between datatypes, etc.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "dynamic_callbacks.h"

void *safe_malloc(uint32_t size)
{
  void *ret = malloc(size);
  if(!ret){
    //ret = memalloc(size);
	//if(!ret){
		MessageBoxA(0, "Malloc failed!", "FFFFUUUUCCCKKK!!!", 0);
	//}
  }else{
    memset(ret, 0, size);
  }
  return ret;
}

void *safe_realloc(void *ptr, uint32_t size)
{
  void *ret = realloc(ptr, size);
  if(!ret)
    DIE_MEM();
  return ret;
}

char *unicode_alloc(const char *string)
{
  size_t i;
  char *unicode;
  size_t unicode_length = (strlen(string) + 1) * 2;

  if(unicode_length < strlen(string))
    DIE("Overflow.");

  unicode = malloc(unicode_length);
  if(!unicode)
    DIE_MEM();

  memset(unicode, 0, unicode_length);
  for(i = 0; i < strlen(string); i++)
  {
    unicode[(i * 2)] = string[i];
  }

  return unicode;
}

char *unicode_alloc_upper(const char *string)
{
  size_t i;
  char *unicode;
  size_t unicode_length = (strlen(string) + 1) * 2;

  if(unicode_length < strlen(string))
    DIE("Overflow.");

  unicode = malloc(unicode_length);
  if(!unicode)
    DIE_MEM();

  memset(unicode, 0, unicode_length);
  for(i = 0; i < strlen(string); i++)
  {
    unicode[(i * 2)] = toupper(string[i]);
  }

  return unicode;
}
