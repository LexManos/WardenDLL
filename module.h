#ifndef MODULE_H
#define MODULE_H

#pragma comment (lib, "zdll.lib") 
#define ZLIB_DLL
#include <zlib.h>
#include "types.h"
#include "stdint.h"
#include "string.h"
#include <windows.h>
#include <stdio.h>
#include "dynamic_callbacks.h"

typedef struct{
  uint32_t maped_size; /*00*/
  uint32_t unknown1;   /*04*/
  uint32_t ref_table;  /*08*/
  uint32_t ref_count;  /*0C*/
  uint32_t init_addr;  /*10*/
  uint32_t unknown3;   /*14*/
  uint32_t unknown4;   /*18*/
  uint32_t lib_table;  /*1C*/
  uint32_t lib_count;  /*20*/
  uint32_t unknown5;   /*24*/
}module_header, *pmodule_header;

typedef struct{
  uint32_t name_address;
  uint32_t function_table;
}library_referance, *plibrary_referance;

typedef struct{
  uint32_t rc4_init;
  uint32_t unload_module;
  uint32_t handle_packet;
  uint32_t tick_count;
}module_exports;

typedef struct{
  uint32_t send_packet;
  uint32_t check_module;
  uint32_t load_module;
  uint32_t mem_alloc;
  uint32_t mem_free;
  uint32_t set_rc4;
  uint32_t get_rc4;
}module_callbacks;

typedef struct{
  module_callbacks *c;
}module_callbacksp;

typedef struct{
  module_exports    *exports;
  uint32_t           unknown1[5];
  module_callbacksp *callbacks;
  uint32_t           unknown2;
  uint8_t            out_key[0x102];
  uint8_t            in_key[0x102];
}module_init_return, *pmodule_init_return;

typedef uint32_t (__fastcall *module_init_t)         (uint32_t callbacks);
typedef uint32_t (__fastcall *module_init_ran_data)  (uint32_t *init_data, uint32_t _set_zero_, uint8_t *data, uint32_t size);
typedef uint8_t* (__fastcall *module_handle_packet_t)(uint32_t *init_data, uint32_t _set_zero_, uint8_t *packet_data, uint32_t length, uint32_t *byte_handled);
typedef uint32_t (__fastcall *module_unload_t)       (uint32_t *init_data);

uint32_t __stdcall module_get_prep_size(uint8_t *data);
uint32_t __stdcall module_prep(uint8_t *source);
uint32_t __stdcall module_init(uint32_t module, uint32_t callbacks);
void     __stdcall module_init_rc4(uint8_t *init_data, uint8_t *data, uint32_t data_length);
uint32_t __stdcall module_get_init_address(uint32_t module);
uint32_t __stdcall module_handle_packet(uint8_t *init_data, uint8_t *data, uint32_t length);
uint32_t __stdcall module_unload(uint8_t *init_data);

#endif
