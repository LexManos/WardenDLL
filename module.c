#pragma once
#include "module.h"

#define module_get_int32(a, b) \
	(*(uint32_t*)(a + (uint32_t)b))

#define module_get_aint32(a, b) \
	(*(uint32_t*)(&a[b]))

#define module_get_int16(a, b) \
	(*(uint16_t*)&a[(uint32_t)b])

#define module_swap_int16(a) \
	(((a & 0xFF00) >> 8) | ((a & 0xFF) << 8))

#define module_set_int32(a, b, c)\
	(*(uint32_t*)(a + b) = c)


int __stdcall module_prep(uint8_t *source){
	uint32_t src_location;
	uint32_t dest_location;
	uint16_t length = 0;
	uint8_t bskip = 0;
	uint16_t *refs;
	uint32_t x = 0;
	uint32_t y = 0;
	library_referance *libs;
	uint8_t *lib;
	HMODULE handle;
	uint32_t function;
	uint32_t func;
	//uint8_t *msgbuff;
	uint32_t dest;
	uint32_t max_size;
	module_header *header = (pmodule_header)source;

	max_size = module_get_prep_size(source);
	dest = memalloc(max_size);
	memset((uint8_t*)dest, 0, max_size);

	//msgbuff = safe_malloc(500);
	//sprintf_s(msgbuff, 500, "Warden Base: 0x%08X\n", (uint32_t)dest); write_to_file(msgbuff);
	
	memcpy((uint8_t*)dest, source, sizeof(module_header));

	src_location = sizeof(module_header) + (header->unknown5 * 12);
	dest_location = module_get_aint32(source, 40);

	//write_to_file("Copying code blocks to module\n");

	while(dest_location < header->maped_size){
		length = module_get_int16(source, src_location);
		src_location += 2;
		if(!bskip){
			memcpy((uint8_t*)(dest + dest_location), source + src_location, length);
			src_location += length;
		}
		bskip = !bskip;
		dest_location += length;
	} 

	refs = (uint16_t*)(dest + header->ref_table);
	dest_location = 0;

	//sprintf_s(msgbuff, 500, "Adjusting %d references to global variables...\n", (int)header->ref_count); write_to_file(msgbuff);

	for(x = 0; x < header->ref_count; x++){
		dest_location += module_swap_int16(refs[x]);
		module_set_int32(dest, dest_location, (module_get_int32(dest, dest_location) % max_size) + dest);
	}

	//write_to_file("Updating API library referances...\n");

	libs = (plibrary_referance)(dest + header->lib_table);
	for(x = 0; x < header->lib_count; x++){
		lib = (uint8_t*)(dest + libs[x].name_address);
		handle = LoadLibrary(lib);

		function = libs[x].function_table;
		while(module_get_int32(dest, function) != 0){
			func = module_get_int32(dest, function);
			if((func & 0x7FFFFFFF) > max_size){
				//sprintf_s(msgbuff, 500, "Attempted to read API from offset pass end of module: 0x%08X\n", func); write_to_file(msgbuff);
				break;
			}
			if(func & 0x80000000){
				y = (uint32_t)GetProcAddress(handle, (LPCSTR)(func & 0x7FFFFFFF));
			}else{
				y = (uint32_t)GetProcAddress(handle, (uint8_t*)(dest + func));
			}
			module_set_int32(dest, function, y);
			function += 4;
		}
	}
	return dest;
}
int __stdcall module_get_init_address(uint32_t module){
	uint32_t x = module_get_int32(module, 0x10);
	return module_get_int32(module, x);
}

int __stdcall module_init(uint32_t address,  uint32_t callbacks){
	module_init_t init = (module_init_t)address;
	return init(callbacks);
}

void __stdcall module_init_rc4(uint8_t *init_data, uint8_t *data, uint32_t data_length){
	module_init_return* init = (module_init_return*)init_data;
	module_init_ran_data rc4_init = (module_init_ran_data)init->exports->rc4_init;
	rc4_init((uint32_t*)init_data, (uint32_t)0, data, data_length);
}


uint32_t __stdcall module_handle_packet(uint8_t *init_data, uint8_t *data, uint32_t length){
	uint32_t handled = -1;
	module_init_return *init = (module_init_return*)init_data;
	module_handle_packet_t handle = (module_handle_packet_t)init->exports->handle_packet;
	handle((uint32_t*)init_data, (uint32_t)0, data, length, &handled);
	return handled;
}

int __stdcall module_get_prep_size(uint8_t *data){return ((pmodule_header)data)->maped_size; }

uint32_t __stdcall module_unload(uint8_t *init_data){
	module_init_return *init = (module_init_return*)init_data;
	module_unload_t mod_unload = (module_unload_t)init->exports->unload_module;
	return mod_unload((uint32_t*)init_data);
}
