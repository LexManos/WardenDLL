#ifndef DYNAMIC_CALLBACKS_C
#define DYNAMIC_CALLBACKS_C
#include "dynamic_callbacks.h"


uint32_t __stdcall memalloc(uint32_t size){
	LPVOID x = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	VirtualLock(x, size);
	return (uint32_t)x;
}
void __stdcall memfree(uint32_t address, uint32_t size){
	VirtualUnlock((uint8_t*)address, size);
	VirtualFree((uint8_t*)address, 0, MEM_RELEASE);
}

void __stdcall module_packet(uint32_t instance, uint32_t packet, uint32_t size){
	warden_instance *ctx = (warden_instance*)instance;
	size += 4;
	send(ctx->socket_handle, "\xff\x5e", 2, 0);
	send(ctx->socket_handle, (uint8_t*)&size, 2, 0);
	send(ctx->socket_handle, (uint8_t*)packet, size - 4, 0);
}

uint32_t __stdcall module_check(uint32_t instance, uint32_t module, uint32_t rc4_key) { return 1; }
uint32_t __stdcall module_load(uint32_t instance, uint32_t rc4_key, uint32_t module, uint32_t size){ return 1; }
uint32_t __stdcall module_malloc(uint32_t instance, uint32_t size)                    { return (uint32_t)safe_malloc(size); }
void __stdcall module_mfree(uint32_t instance, uint32_t address)                      { free((uint8_t*)address); }
uint32_t __stdcall module_setrc4(uint32_t instance, uint32_t ptr_keys, uint32_t size) { return 1; }
uint32_t __stdcall module_getrc4(uint32_t instance, uint32_t ptr_keys, uint32_t *size){ return 1; }

uint32_t get_callback_packet(uint32_t new_function, uint32_t instance){
	uint32_t function_address = (uint32_t)module_packet;
	uint32_t function_call    = new_function + 22;
	memcpy((uint8_t*)new_function, "\xFF\x74\x24\x08\xFF\x74\x24\x08\x68\x0B\xAD\xC0\xDE\xFF\x15\x0B\xAD\xC0\xDE\xC2\x08\x00\x00\x00\x00\x00", 26);
	memcpy((uint8_t*)(new_function+9),  &instance, 4);
	memcpy((uint8_t*)(new_function+15), &function_call, 4);
	memcpy((uint8_t*)(new_function+22), &function_address, 4);
	return new_function;
}

uint32_t get_callback_check(uint32_t new_function, uint32_t instance){
	uint32_t function_address = (uint32_t)module_check;
	uint32_t function_call    = new_function + 22;
	memcpy((uint8_t*)new_function, "\xFF\x74\x24\x08\xFF\x74\x24\x08\x68\x0B\xAD\xC0\xDE\xFF\x15\x0B\xAD\xC0\xDE\xC2\x08\x00\x00\x00\x00\x00", 26);
	memcpy((uint8_t*)(new_function+9),  &instance, 4);
	memcpy((uint8_t*)(new_function+15), &function_call, 4);
	memcpy((uint8_t*)(new_function+22), &function_address, 4);
	return new_function;
}

uint32_t get_callback_load(uint32_t new_function, uint32_t instance){
	uint32_t function_address = (uint32_t)module_load;
	uint32_t function_call    = new_function + 26;
	memcpy((uint8_t*)new_function, "\xFF\x74\x24\x0C\xFF\x74\x24\x0C\xFF\x74\x24\x0C\x68\x0B\xAD\xC0\xDE\xFF\x15\x0B\xAD\xC0\xDE\xC2\x0C\x00\x00\x00\x00\x00", 30);
	memcpy((uint8_t*)(new_function+13), &instance, 4);
	memcpy((uint8_t*)(new_function+19), &function_call, 4);
	memcpy((uint8_t*)(new_function+26), &function_address, 4);
	return new_function;
}

uint32_t get_callback_malloc(uint32_t new_function, uint32_t instance){
	uint32_t function_address = (uint32_t)module_malloc;
	uint32_t function_call    = new_function + 18;
	memcpy((uint8_t*)new_function, "\xFF\x74\x24\x04\x68\x0B\xAD\xC0\xDE\xFF\x15\x0B\xAD\xC0\xDE\xC2\x04\x00\x00\x00\x00\x00", 22);
	memcpy((uint8_t*)(new_function+5),  &instance, 4);
	memcpy((uint8_t*)(new_function+11), &function_call, 4);
	memcpy((uint8_t*)(new_function+18), &function_address, 4);
	return new_function;
}

uint32_t get_callback_mfree(uint32_t new_function, uint32_t instance){
	uint32_t function_address = (uint32_t)module_mfree;
	uint32_t function_call    = new_function + 18;
	memcpy((uint8_t*)new_function, "\xFF\x74\x24\x04\x68\x0B\xAD\xC0\xDE\xFF\x15\x0B\xAD\xC0\xDE\xC2\x04\x00\x00\x00\x00\x00", 22);
	memcpy((uint8_t*)(new_function+5),  &instance, 4);
	memcpy((uint8_t*)(new_function+11), &function_call, 4);
	memcpy((uint8_t*)(new_function+18), &function_address, 4);
	return new_function;
}

uint32_t get_callback_setrc4(uint32_t new_function, uint32_t instance){
	uint32_t function_address = (uint32_t)module_setrc4;
	uint32_t function_call    = new_function + 22;
	memcpy((uint8_t*)new_function, "\xFF\x74\x24\x08\xFF\x74\x24\x08\x68\x0B\xAD\xC0\xDE\xFF\x15\x0B\xAD\xC0\xDE\xC2\x08\x00\x00\x00\x00\x00", 26);
	memcpy((uint8_t*)(new_function+9),  &instance, 4);
	memcpy((uint8_t*)(new_function+15), &function_call, 4);
	memcpy((uint8_t*)(new_function+22), &function_address, 4);
	return new_function;
}

uint32_t get_callback_getrc4(uint32_t new_function, uint32_t instance){
	uint32_t function_address = (uint32_t)module_getrc4;
	uint32_t function_call    = new_function + 22;
	memcpy((uint8_t*)new_function, "\xFF\x74\x24\x08\xFF\x74\x24\x08\x68\x0B\xAD\xC0\xDE\xFF\x15\x0B\xAD\xC0\xDE\xC2\x08\x00\x00\x00\x00\x00", 26);
	memcpy((uint8_t*)(new_function+9),  &instance, 4);
	memcpy((uint8_t*)(new_function+15), &function_call, 4);
	memcpy((uint8_t*)(new_function+22), &function_address, 4);
	return new_function;
}

#endif