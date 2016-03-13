#ifndef DYNAMIC_CALLBACKS_H
#define DYNAMIC_CALLBACKS_H
#include <stdio.h>
#include "types.h"
#include "stdint.h"
#include "string.h"
#include <windows.h>
#include "warden.h"
#include "types.h"

uint32_t __stdcall memalloc(uint32_t size);
void     __stdcall memfree(uint32_t address, uint32_t size);

void     __stdcall module_packet(uint32_t instance, uint32_t packet, uint32_t size);
uint32_t __stdcall module_check (uint32_t instance, uint32_t module, uint32_t rc4_key);
uint32_t __stdcall module_load  (uint32_t instance, uint32_t rc4_key, uint32_t module, uint32_t size);
uint32_t __stdcall module_malloc(uint32_t instance, uint32_t size);
void     __stdcall module_mfree (uint32_t instance, uint32_t address);
uint32_t __stdcall module_setrc4(uint32_t instance, uint32_t ptr_keys, uint32_t size);
uint32_t __stdcall module_getrc4(uint32_t instance, uint32_t ptr_keys, uint32_t *size);

uint32_t get_callback_packet(uint32_t new_function, uint32_t instance);
uint32_t get_callback_check (uint32_t new_function, uint32_t instance);
uint32_t get_callback_load  (uint32_t new_function, uint32_t instance);
uint32_t get_callback_malloc(uint32_t new_function, uint32_t instance);
uint32_t get_callback_mfree (uint32_t new_function, uint32_t instance);
uint32_t get_callback_setrc4(uint32_t new_function, uint32_t instance);
uint32_t get_callback_getrc4(uint32_t new_function, uint32_t instance);
#endif