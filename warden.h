#pragma once

#include "types.h"
#include "stdint.h"
#include "string.h"
#include <windows.h>
#include <stdio.h>
#include "module.h"
#include "dynamic_callbacks.h"
#include "mediv_random.h"
#include "rc4.h"
#include "md5.h"
#include "buffer.h"
#include "config.h"
#include "log.h"

#define WARDEN_SEND (0x00)
#define WARDEN_RECV (0x01)
#define WARDEN_BNCS (0x02)

#define SID_AUTH_INFO  (0x50)
#define SID_AUTH_CHECK (0x51)
#define SID_WARDEN     (0x5E)

#define MODULE_INFORMATION (0x00)
#define MODULE_TRANSFER    (0x01)
#define CHEAT_CHECKS       (0x02)
#define NEW_CRYPT_KEYS     (0x05)


typedef enum{
    WARDEN_IGNORE = 0,              //Not a warden packet, Handle internally
	WARDEN_SUCCESS,                 //All Went Well, Don't handle the packet Internally
	WARDEN_UNKNOWN_PROTOCOL,        //Not used, will be when adding support for MCP/UDP
	WARDEN_UNKNOWN_SUBID,           //Unknown Sub-ID [Not 0x00, 0x01, 0x02, or 0x05]
	WARDEN_RAW_FAILURE,             //The module was not able to handle the packet itself
	WARDEN_PACKET_FAILURE,          //Something went HORRIBLY wrong in warden_packet, should NEVER happen.
	WARDEN_INIT_FAILURE,            //Calling Init() in the module failed
	WARDEN_LOAD_FILE_FAILURE,       //Could not load module from file [Not to bad, prolly just dosen't exist]
	WARDEN_LOAD_MD5_FAILURE,        //Failed MD5 checksum when loading module [Either Bad tranfer or HD file corrupt]
	WARDEN_LOAD_INVALID_SIGNATURE,  //Module failed RSA verification
	WARDEN_LOAD_DECOMPRESS_FAILURE, //Module failed to decompress properly
	WARDEN_LOAD_PREP_FAILURE,       //Module prepare failed, Usually if module is corrupt
	WARDEN_CHECK_UNKNOWN_COMMAND,   //Unknown sub-command in CHEAT_CHECKS
	WARDEN_CHECK_TO_MANY_LIBS,      //There were more then 4 libraries in a single 0x02 packet [this is eww yes, but I'll figure out a beter way later]
	WARDEN_MEM_UNKNOWN_PRODUCT,     //The product from 0x50 != WC3, SC, or D2
	WARDEN_MEM_UNKNOWN_SEGMENT,     //Could not read segment from ini file
	WARDEN_INVALID_INSTANCE,        //If the instance passed to any api is invalid (0)
	WARDEN_MAX = 0xffffffff
};

typedef enum{
	CONFIG_SAVE_CHECKS    = 1,
	CONFIG_SAVE_UNKNOWN   = 2,
	CONFIG_LOG_CHECKS     = 4,
	CONFIG_LOG_PACKETS    = 8,
	CONFIG_DEBUG_MODE     = 16,
	CONFIG_USE_GAME_FILES = 32,
	CONFIG_MAX = 0xFFFFFFFF
};

typedef struct{
  uint32_t send_packet;
  uint32_t check_module;
  uint32_t load_module;
  uint32_t mem_alloc;
  uint32_t mem_free;
  uint32_t set_rc4;
  uint32_t get_rc4;
}callbacks_t;
typedef struct{
  callbacks_t *c;
}callbacksp_t;

typedef struct{
	uint32_t     socket_handle;
	callbacksp_t *callbacks;
	uint32_t     product;
	uint8_t      *seed;
	uint32_t     seed_len;
	uint8_t      *in_key;
	uint8_t      *out_key;
	uint8_t      *module_md5;
	uint8_t      *module_seed;
	uint32_t     module;
	uint32_t     module_size;
	uint32_t     module_position;
	uint32_t     init_data;
	uint8_t      PAGE_CHECK_A;
	uint8_t      MEM_CHECK;
	uint8_t      *data_file;
	uint32_t     config;
	uint8_t      *save_folder;
}warden_instance;

void warden_init_rc4keys(warden_instance *ctx);
void warden_send_packet(warden_instance *ctx, const uint8_t *data, uint16_t size);
void warden_save_file(warden_instance *ctx, uint32_t file_step);
uint32_t warden_load_module(warden_instance *ctx);
uint32_t warden_mem_check(warden_instance *ctx, buffer_t *buffer, buffer_t *out_buffer, uint8_t *lib);
uint32_t warden_page_check(warden_instance *ctx, buffer_t *buffer, buffer_t *out_buffer);

uint32_t warden_packet(warden_instance *ctx, uint8_t *packet_data, uint32_t size);
uint32_t warden_module_information(warden_instance *ctx, buffer_t *buffer);
uint32_t warden_module_transfer(warden_instance *ctx, buffer_t *buffer);
uint32_t warden_cheat_check(warden_instance *ctx, buffer_t *buffer);
uint32_t warden_handle_raw(warden_instance *ctx, uint8_t *data, uint32_t length);
uint32_t warden_unknown(warden_instance *ctx, uint8_t opcode, buffer_t *buffer);
uint8_t *warden_read_game_file(warden_instance *ctx, uint8_t *library, uint32_t address, uint8_t length, uint8_t *header, uint8_t *key, uint32_t adjustment);

uint32_t __stdcall warden_init(uint32_t socket_handle);
uint32_t __stdcall warden_data(uint32_t instance, uint32_t direction, uint32_t packet_id, uint8_t *packet_data, uint32_t size);
uint32_t __stdcall warden_cleanup(uint32_t instance);
uint32_t __stdcall warden_config(uint32_t instance, uint32_t config_bit, uint8_t enabled);
uint32_t __stdcall warden_set_data_file(uint32_t instance, uint8_t *file, uint32_t length);