#include "warden.h"


void write_to_file(const uint8_t *data){
	FILE *fp;
	fopen_s(&fp, "WardenLog.txt", "a");
	fwrite(data, 1, strlen(data), fp);
	fclose(fp);
}
uint8_t *to_hex(uint8_t *data, uint32_t size, BOOLEAN spaces){
	uint8_t *buff = safe_malloc(size * (spaces == TRUE ? 3 : 2));
	uint32_t x = 0;
	
	for(x = 0; x < size; x++){
		if(spaces == TRUE)
			sprintf_s((uint8_t*)(buff + (3 * x)), 4, "%02X ", data[x]);
		else
			sprintf_s((uint8_t*)(buff + (2 * x)), 4, "%02X", data[x]);
	}
	return buff;
}

uint32_t __stdcall warden_init(uint32_t socket_handle){
	warden_instance *instance = safe_malloc(sizeof(warden_instance));
	uint32_t code_segment     = memalloc(0x1c0);
	memset(instance, 0, sizeof(warden_instance));
	instance->socket_handle   = socket_handle;
	instance->callbacks       = safe_malloc(sizeof(callbacksp_t));
	instance->callbacks->c    = safe_malloc(sizeof(callbacks_t));

	
	instance->callbacks->c->send_packet  = get_callback_packet(code_segment + 0x000, (uint32_t)instance);
	instance->callbacks->c->check_module = get_callback_check (code_segment + 0x040, (uint32_t)instance);
	instance->callbacks->c->load_module  = get_callback_load  (code_segment + 0x080, (uint32_t)instance);
	instance->callbacks->c->mem_alloc    = get_callback_malloc(code_segment + 0x0C0, (uint32_t)instance);
	instance->callbacks->c->mem_free     = get_callback_mfree (code_segment + 0x100, (uint32_t)instance);
	instance->callbacks->c->set_rc4      = get_callback_setrc4(code_segment + 0x140, (uint32_t)instance);
	instance->callbacks->c->get_rc4      = get_callback_getrc4(code_segment + 0x180, (uint32_t)instance);
	return (uint32_t)instance;
}

uint32_t __stdcall warden_data(uint32_t instance, uint32_t direction, uint32_t packet_id, uint8_t *packet_data, uint32_t size){
	uint32_t ret = WARDEN_IGNORE;
	warden_instance *ctx = (warden_instance*)instance;

	if(instance == 0)
		return WARDEN_INVALID_INSTANCE;

	if((direction & WARDEN_BNCS) == WARDEN_BNCS){
		if((direction & WARDEN_RECV) == WARDEN_RECV){
			if(packet_id == SID_WARDEN)
				ret = warden_packet(ctx, packet_data, size);
		}else{
			switch(packet_id){
				case SID_AUTH_INFO: 
					ctx->product = (*(uint32_t*)(packet_data + 8));
					break;

				case SID_AUTH_CHECK:
					ctx->seed = safe_malloc(4);
					memcpy(ctx->seed, packet_data + 36, 4);
					ctx->seed_len = 4;
					warden_init_rc4keys(ctx);
					break;
			}
		}
	}
	return ret;
}

uint32_t __stdcall warden_cleanup(uint32_t instance){
	warden_instance *ctx = (warden_instance*)instance;

	if(ctx == NULL) return WARDEN_INVALID_INSTANCE;
	if(ctx->in_key      != NULL) free(ctx->in_key);
	if(ctx->out_key     != NULL) free(ctx->out_key);
	if(ctx->seed        != NULL) free(ctx->seed);
	if(ctx->init_data   != 0   ) module_unload((uint8_t*)ctx->init_data);
	if(ctx->module      != 0   ) memfree(ctx->module, ctx->module_size);
	if(ctx->module_md5  != NULL) free(ctx->module_md5);
	if(ctx->module_seed != NULL) free(ctx->module_seed);
	if(ctx->data_file   != NULL) free(ctx->data_file);
	if(ctx->callbacks){
		memfree(ctx->callbacks->c->send_packet, 0x1000);
		free(ctx->callbacks);
	}
	free(ctx);
	return WARDEN_SUCCESS;
}

void warden_init_rc4keys(warden_instance *ctx){
	mediv_random_context *rnd = safe_malloc(sizeof(mediv_random_context));
	uint8_t *out_seed = safe_malloc(0x10);
	uint8_t *in_seed  = safe_malloc(0x10);
	ctx->out_key = safe_malloc(0x102);
	ctx->in_key  = safe_malloc(0x102);

	mediv_random_init(rnd, ctx->seed, ctx->seed_len);
	mediv_random_get_bytes(rnd, out_seed, 0x10);
	mediv_random_get_bytes(rnd, in_seed,  0x10);

	rc4_init_old(ctx->out_key, out_seed, 0x10);
	rc4_init_old(ctx->in_key,  in_seed,  0x10);

	free(out_seed);
	free(in_seed);
}

uint32_t warden_packet(warden_instance *ctx, uint8_t *packet_data, uint32_t size){
	buffer_t *buffer;
	uint8_t   opcode;
	uint32_t  ret = WARDEN_PACKET_FAILURE;
	uint8_t  *raw_data = safe_malloc(size);
	uint8_t *debug;

	memcpy(raw_data, packet_data, size); //Keep raw data, To send to Handle_Raw
	if(ctx->init_data != 0) 
		memcpy((uint8_t*)(ctx->init_data + 0x122), ctx->in_key,  0x102); //Update in-key for Handle_Raw

	rc4_crypt_old(ctx->in_key, packet_data, size);

	if((ctx->config & CONFIG_LOG_PACKETS) == CONFIG_LOG_PACKETS){
		debug = safe_malloc(0x200);
		sprintf_s(debug, 0x200, "Received 0x%04X bytes from battle.net in Warden request:\n%s\n\n", size, to_hex(packet_data, size, TRUE));
		write_to_file(debug);
		free(debug);
	}

	buffer = buffer_create_with_data(BO_LITTLE_ENDIAN, packet_data, (uint16_t)size);

	opcode = buffer_read_next_int8(buffer);
	switch(opcode){
		case MODULE_INFORMATION: ret = warden_module_information(ctx, buffer); break;
		case MODULE_TRANSFER:    ret = warden_module_transfer(ctx, buffer);    break;
		case CHEAT_CHECKS:		 ret = warden_cheat_check(ctx, buffer);        break;
		case NEW_CRYPT_KEYS:     ret = warden_handle_raw(ctx, raw_data, size); break;
		default:                 ret = warden_unknown(ctx, opcode, buffer);    break;
	}

	buffer_destroy(buffer);
	free(raw_data);
	return ret;
}

uint8_t *to_string(uint8_t *data){
	uint32_t length;
	uint8_t *buff;
	uint32_t x = 0;


	if(data == NULL) 
		return NULL;

	length = strlen(data) / 2;
	buff   = safe_malloc(length);

	for(x = 0; x < length; x++){
		sscanf_s(data, "%02x", &buff[x], 1);
		data += 2;
	}
	return buff;
}

uint32_t warden_module_information(warden_instance *ctx, buffer_t *buffer){
	/**************************************
	 * MEDIV_MODULE_INFORMATION (0x00)    *
	 *------------------------------------*
	 *(BYTE[16]) MD5 Checksum             *
	 *(BYTE[16]) Module RC4 Seed          *
	 *(DWORD)    Module Compressed Length *
	 **************************************/
	uint32_t ret;
	uint8_t *debug;
	ctx->module_md5  = safe_malloc(0x10);
	ctx->module_seed = safe_malloc(0x10);

	buffer_read_next_bytes(buffer, ctx->module_md5,  0x10);
	buffer_read_next_bytes(buffer, ctx->module_seed, 0x10);

	if((ctx->config & CONFIG_DEBUG_MODE) == CONFIG_DEBUG_MODE){
		debug = safe_malloc(0x300);
		sprintf_s(debug, 0x300, "Module Information:\n\tMD5:    %s\n\tRC4:    %s\n", to_hex(ctx->module_md5, 0x10, FALSE), to_hex(ctx->module_seed, 0x10, FALSE));
		write_to_file(debug);
		free(debug);
	}
	
	ret = warden_load_module(ctx);
	if(ret != WARDEN_SUCCESS){
		if(ctx->module != 0) memfree(ctx->module, ctx->module_size);
		ctx->module_size = buffer_read_next_int32(buffer);
		
		if((ctx->config & CONFIG_DEBUG_MODE) == CONFIG_DEBUG_MODE){
			debug = safe_malloc(0x80);
			sprintf_s(debug, 0x80, "\tLength: 0x%08X\n", ctx->module_size);
			write_to_file(debug);
			free(debug);
		}

		ctx->module_position = 0;
		ctx->module = memalloc(ctx->module_size);
		warden_send_packet(ctx, "\x00", 1);
	}else{
		ctx->init_data = module_init(module_get_init_address(ctx->module) + ctx->module, (uint32_t)ctx->callbacks);

		if(ctx->init_data != 0){
			module_init_rc4((uint8_t*)ctx->init_data, ctx->seed, ctx->seed_len);
			warden_send_packet(ctx, "\x01", 1);
		}else{
			warden_send_packet(ctx, "\x00", 1);
		}
	}

	return WARDEN_SUCCESS;
}

uint32_t warden_module_transfer(warden_instance *ctx, buffer_t *buffer){
	/**********************************
	 * MEDIV_MODULE_TRANSFER (0x01)   *
	 *--------------------------------*
	 * S->C:                          *
	 *  (Word) Payload Length         *
	 *  (Void)  Payload               *
	 *                                *
	 * C->S: (When tranfer finishes)  *
	 *  (Byte) Status                 *
	 *     - 0: Something went wrong  *
	 *     - 1: Module loaded         * 
	 **********************************/
	uint32_t address = 0;
	uint32_t ret = WARDEN_SUCCESS;
	uint32_t data_length = buffer_read_next_int16(buffer);
	buffer_read_next_bytes(buffer, (uint8_t*)(ctx->module + ctx->module_position), (uint16_t)data_length);
	ctx->module_position += data_length;

	if(ctx->module_position == ctx->module_size){
		ret = warden_load_module(ctx);

		if(ret == WARDEN_SUCCESS){
			address = module_get_init_address(ctx->module) + ctx->module;
			ctx->init_data = module_init(address, (uint32_t)ctx->callbacks);

			if(ctx->init_data != 0){
				module_init_rc4((uint8_t*)ctx->init_data, ctx->seed, ctx->seed_len);
				warden_send_packet(ctx, "\x01", 1);
				ret = WARDEN_SUCCESS;
			}else{
				warden_send_packet(ctx, "\x00", 1);
				ret = WARDEN_INIT_FAILURE;
			}
		}else{
			warden_send_packet(ctx, "\x00", 1);
		}
	}
	return ret;
}

uint32_t warden_unknown(warden_instance *ctx, uint8_t opcode, buffer_t *buffer){
	/***************************************
	 *Unknown Sub-Command, In the future   *
	 *attempt to have the module handle it.*
	 ***************************************/
	return WARDEN_UNKNOWN_SUBID;
}

void warden_send_packet(warden_instance *ctx, const uint8_t *data, uint16_t size){
	uint8_t *pdata = safe_malloc(size);
	uint8_t *debug;
	memcpy(pdata, data, size);

	if((ctx->config & CONFIG_LOG_PACKETS) == CONFIG_LOG_PACKETS){
		debug = safe_malloc(0x200);
		sprintf_s(debug, 0x200, "Sending 0x%04X bytes to battle.net in Warden response:\n%s\n\n", size, to_hex(data, size, TRUE));
		write_to_file(debug);
		free(debug);
	}

	rc4_crypt_old(ctx->out_key, pdata, (uint32_t)size);

	size += 4;
	send(ctx->socket_handle, "\xff\x5e", 2, 0);
	send(ctx->socket_handle, (uint8_t*)&size, 2, 0);
	send(ctx->socket_handle, pdata, size - 4, 0);
	free(pdata);
}

void warden_save_file(warden_instance *ctx, uint32_t file_step){
	FILE *fp;
	uint32_t error;
	uint8_t *path = safe_malloc(0x100);
	uint8_t *name = to_hex(ctx->module_md5, 0x10, FALSE);
	error = CreateDirectory("./Warden/", NULL);

	if(error == 0){
		error = GetLastError();
		if(error != ERROR_ALREADY_EXISTS){
			free(path);
			return;
		}
	}

	switch(file_step){
		case 1:  sprintf_s(path, 0x100, "./Warden/%s.bin", name); break;
		case 2:  sprintf_s(path, 0x100, "./Warden/%s.temp1.bin", name); break;
		case 3:  sprintf_s(path, 0x100, "./Warden/%s.temp2.bin", name); break;
		case 4:  sprintf_s(path, 0x100, "./Warden/%s.mod", name); break;
		case 5:  sprintf_s(path, 0x100, "./Warden/%s.key", name); break;
		default: sprintf_s(path, 0x100, "./Warden/%s.bin", name); break;
	}
	fopen_s(&fp, path, "wb");
	if(file_step == 5) fwrite(ctx->module_seed , 1, 0x10, fp);
	else               fwrite((uint8_t*)ctx->module, 1, ctx->module_size, fp); 
	fclose(fp);

	free(path);
}

uint32_t warden_load_module(warden_instance *ctx){
	uint32_t size;
	uint32_t temp_module;
	FILE    *fp;
	uint32_t result;

	if(ctx->module == 0){
		uint8_t *path = safe_malloc(0x30);
		sprintf_s(path, 0x30, "./Warden/%s.bin", to_hex(ctx->module_md5, 0x10, FALSE));

		fopen_s(&fp, path, "rb");
		if(fp != NULL){
			fseek(fp, 0, SEEK_END);
			ctx->module_size = ftell(fp);
			rewind(fp);
			ctx->module = memalloc(ctx->module_size);
			result = fread((uint8_t*)ctx->module, 1, ctx->module_size, fp);
			fclose(fp);

			if(result != ctx->module_size)
				return WARDEN_LOAD_FILE_FAILURE;
		}else{
			return WARDEN_LOAD_FILE_FAILURE;
		}
	}

	if(md5_verify_data((uint8_t*)ctx->module, ctx->module_size, ctx->module_md5) == 1){
		warden_save_file(ctx, 1); //Save Module
		warden_save_file(ctx, 5); //Save Key
		rc4_crypt_data((uint8_t*)ctx->module, ctx->module_size, ctx->module_seed, 0x10);
		warden_save_file(ctx, 2);

		if((*(uint32_t*)(ctx->module + ctx->module_size - 0x104)) == 'SIGN'){
			size        = *(uint32_t*)(ctx->module);
			temp_module = memalloc(size);
			if(uncompress((uint8_t*)temp_module, &size, (uint8_t*)(ctx->module + 4), ctx->module_size - 0x108) == 0){
				memfree(ctx->module, ctx->module_size);
				ctx->module      = temp_module;
				ctx->module_size = size;
				//warden_save_file(ctx, 3);

				size = module_get_prep_size((uint8_t*)ctx->module);
				temp_module = module_prep((uint8_t*)ctx->module);
				if(temp_module != 0){
					memfree(ctx->module, ctx->module_size);
					ctx->module      = temp_module;
					ctx->module_size = size;
					//warden_save_file(ctx, 4);
					return WARDEN_SUCCESS;
				}else{
					return WARDEN_LOAD_PREP_FAILURE;
				}
			}else{
				return WARDEN_LOAD_DECOMPRESS_FAILURE;
			}
		}else{
			return WARDEN_LOAD_INVALID_SIGNATURE;
		}
	}else{
		return WARDEN_LOAD_MD5_FAILURE;
	}
}

uint32_t warden_handle_raw(warden_instance *ctx, uint8_t *data, uint32_t length){
	/************************************************************************************
	 *Raw, This will attempt to have the module itself handle the packet.               *
	 *Currently this is needed for 0x05 as documentation on this packet is not avalible.*
	 ************************************************************************************/
	uint32_t handled = 0;
	if(ctx->init_data == 0) 
		return WARDEN_RAW_FAILURE;

	memcpy((uint8_t*)(ctx->init_data + 0x020), ctx->out_key, 0x102);
	handled = module_handle_packet((uint8_t*)ctx->init_data, data, length);
	if(handled == length){
		memcpy(ctx->out_key, (uint8_t*)(ctx->init_data + 0x020), 0x102);
		memcpy(ctx->in_key,  (uint8_t*)(ctx->init_data + 0x122), 0x102);
		return WARDEN_SUCCESS;
	}else{
		return WARDEN_RAW_FAILURE;
	}
}

uint32_t warden_cheat_check(warden_instance *ctx, buffer_t *buffer){
	/**************************************
	 * CHEAT_CHECKS (0x02)                *
	 *------------------------------------*
	 * S->C:                              *
	 *  (PString[]) Libraries             *
	 *  (Byte)      Check Type            *
	 *    -PageCheckA                     *
	 *     (DWORD)    Seed                *
	 *     (Byte[20]) SHA1                *
	 *     (DWORD)    Address             *
	 *     (Byte)     Length              *
	 *    -MemCheck                       *
	 *     (Byte)  Library                *
	 *     (DWORD) Address                *
	 *     (Byte)  Length                 *
	 *  (Byte) XOr Code                   *
	 **************************************/
	uint8_t opcode;
	uint8_t xor;
	uint8_t length;
	uint32_t lib_count;
	uint32_t x = 0;
	uint32_t mem = memalloc(0x400);
	buffer_t *out_buffer = buffer_create(BO_LITTLE_ENDIAN);
	buffer_t *temp_buffer;
	uint8_t  *temp_data = (uint8_t*)(mem + 0x300);
	uint8_t index;
	uint32_t ret = WARDEN_SUCCESS;
	uint32_t rettmp = 0;
	uint8_t *debug = (uint8_t*)memalloc(0x180);
	uint8_t *libs[] = {
		(uint8_t*)0,
		(uint8_t*)(mem + 0x000), 
		(uint8_t*)(mem + 0x100), 
		(uint8_t*)(mem + 0x200)
	};

	length = buffer_read_next_int8(buffer);

	while(length > 0){
		if(x > 3){
			ret = WARDEN_CHECK_TO_MANY_LIBS;
			break;
		}
		buffer_read_next_bytes(buffer, libs[++x], length);
		if((ctx->config & CONFIG_LOG_CHECKS) == CONFIG_LOG_CHECKS){
			sprintf_s(debug, 0x180, "Library: %d %s\r\n", x, libs[x]);
			write_to_file(debug);
		}
		length = buffer_read_next_int8(buffer);
	}

	lib_count = x;
	xor = buffer_read_int8_at(buffer, buffer_get_length(buffer) - 1);

	while(buffer_can_read_int16(buffer) == TRUE && ((ret == WARDEN_SUCCESS) | ((ctx->config & CONFIG_DEBUG_MODE) == CONFIG_DEBUG_MODE))){
		opcode = buffer_read_next_int8(buffer) ^ xor;

		if(ctx->MEM_CHECK == 0 || ctx->PAGE_CHECK_A == 0){
			buffer_peek_next_bytes(buffer, temp_data, 6);
			temp_buffer = buffer_create_with_data(BO_LITTLE_ENDIAN, temp_data, 6);

			index  = buffer_read_next_int8(temp_buffer);
			x      = buffer_read_next_int32(temp_buffer);
			length = buffer_read_next_int8(temp_buffer);
			buffer_destroy(temp_buffer);

			if(index > lib_count)          ctx->PAGE_CHECK_A = opcode;
			else{
				if(index > 0){
					if(length > 0x20)      ctx->PAGE_CHECK_A = opcode;
					else{
						if(x > 0x01000000) ctx->PAGE_CHECK_A = opcode;
						else               ctx->MEM_CHECK    = opcode;
					}
				}else{
					if(length > 0x20)                        ctx->PAGE_CHECK_A = opcode;
					else{
						if(x < 0x00400000 || x > 0x60000000) ctx->PAGE_CHECK_A = opcode;
						else                                 ctx->MEM_CHECK    = opcode;
					}
				}
			}
		}

		if(opcode == ctx->MEM_CHECK){
			index = buffer_peek_next_int8(buffer);
			rettmp = warden_mem_check(ctx, buffer, out_buffer, libs[index]);
		}else if(opcode == ctx->PAGE_CHECK_A){
			rettmp = warden_page_check(ctx, buffer, out_buffer);
		}else{
			rettmp = warden_page_check(ctx, buffer, out_buffer);
		}

		if(rettmp != WARDEN_SUCCESS){
			ret = rettmp;
		}
	}
	
	if(ret == WARDEN_SUCCESS){
		temp_buffer = buffer_create(BO_LITTLE_ENDIAN);
		buffer_add_int8(temp_buffer, '\x02');
		buffer_add_int16(temp_buffer, buffer_get_length(out_buffer));
		buffer_add_int32(temp_buffer, sha1_checksum((uint8_t*)(out_buffer->data), buffer_get_length(out_buffer), 0));
		buffer_add_bytes(temp_buffer, out_buffer->data, buffer_get_length(out_buffer));
		warden_send_packet(ctx, temp_buffer->data, buffer_get_length(temp_buffer));

		buffer_destroy(temp_buffer);
	}
	buffer_destroy(out_buffer);
	memfree(mem, 0x400);
	memfree((uint32_t)debug, 0x180);

	return ret;
}

uint32_t warden_page_check(warden_instance *ctx, buffer_t *buffer, buffer_t *out_buffer){
	/**************************************
     *    -PageCheckA                     *
	 *     (DWORD)    Seed                *
	 *     (Byte[20]) SHA1                *
	 *     (DWORD)    Address             *
	 *     (Byte)     Length              *
	 **************************************/
	uint8_t *temp = safe_malloc(0x100);
	uint32_t seed = 0;
	uint8_t *SHA1 = safe_malloc(20);
	uint32_t address = 0;
	uint8_t  length = 0;

	seed    = buffer_read_next_int32(buffer);
	buffer_read_next_bytes(buffer, SHA1, 20);
	address = buffer_read_next_int32(buffer);
	length  = buffer_read_next_int8(buffer);
	buffer_add_int8(out_buffer, '\xE9');

	if((ctx->config & CONFIG_LOG_CHECKS) == CONFIG_LOG_CHECKS){
		sprintf_s(temp, 0x100, "Page Check: %d @ 0x%08X SHA1: %s Seed: 0x%08X\n", length, address, to_hex(SHA1, 20, FALSE), seed);
		write_to_file(temp);
	}

	free(temp);
	free(SHA1);
	return WARDEN_SUCCESS; //Really, this can't fail :P
}

uint32_t warden_mem_check(warden_instance *ctx, buffer_t *buffer, buffer_t *out_buffer, uint8_t *lib){
	/**************************************
	 *    -MemCheck                       *
	 *     (Byte)  Library                *
	 *     (DWORD) Address                *
	 *     (Byte)  Length                 *
	 **************************************/

	uint8_t *key     = safe_malloc(0x20);
	uint8_t *header  = safe_malloc(0x20);
	uint8_t *data;
	uint8_t  index   = buffer_read_next_int8(buffer);
	uint32_t address = buffer_read_next_int32(buffer);
	uint8_t  length  = buffer_read_next_int8(buffer);
	uint32_t ret     = WARDEN_SUCCESS;
	uint8_t *debug   = safe_malloc(0x100);

	if(ctx->product == 'WAR3' || ctx->product == 'W3XP'){
		if(index == 0) sprintf_s(header, 0x20, "WAR3_MEM_CHECK");
		else           sprintf_s(header, 0x20, "WAR3_%s", lib);
	}else if(ctx->product == 'STAR' || ctx->product == 'SEXP'){
		if(index == 0) sprintf_s(header, 0x20, "STAR_MEM_CHECK");
		else           sprintf_s(header, 0x20, "STAR_%s", lib);
	}else if(ctx->product == 'D2DV'){
		if(index == 0) sprintf_s(header, 0x20, "D2DV_MEM_CHECK");
		else           sprintf_s(header, 0x20, "D2DV_%s", lib);
	}else if(ctx->product == 'D2XP'){
		if(index == 0) sprintf_s(header, 0x20, "D2XP_MEM_CHECK");
		else           sprintf_s(header, 0x20, "D2XP_%s", lib);
	}else{
		ret = WARDEN_MEM_UNKNOWN_PRODUCT;
	}

	if(ret == WARDEN_SUCCESS || ret == WARDEN_MEM_UNKNOWN_SEGMENT){
		sprintf_s(key, 0x20, "%02X_%08X", length, address);
		data = read_ini((ctx->data_file != NULL ? ctx->data_file : "Warden.ini"), header, key, NULL);
		data = to_string(data);

		if((ctx->config & CONFIG_LOG_CHECKS) == CONFIG_LOG_CHECKS){
			sprintf_s(debug, 0x100, "Mem Check: %s %s - %s\n", header, key, (data != NULL ? to_hex(data, length, TRUE) : "UNKNOWN"));
			write_to_file(debug);
		}

		if(data == NULL){
			if((ctx->config & CONFIG_USE_GAME_FILES) == CONFIG_USE_GAME_FILES){

				data = warden_read_game_file(ctx, (index == 0 ? "Default" : lib), address, length, header, key, (index == 0 ? 0x00400000 : 0));
				if(data == NULL){
					buffer_add_int8(out_buffer, '\x01');
					ret = WARDEN_MEM_UNKNOWN_SEGMENT;
				}else{
					buffer_add_int8(out_buffer, '\x00');
					buffer_add_bytes(out_buffer, data, length);
				}
			}else{
				buffer_add_int8(out_buffer, '\x01');
				ret = WARDEN_MEM_UNKNOWN_SEGMENT;
			}
		}else{
			buffer_add_int8(out_buffer, '\x00');
			buffer_add_bytes(out_buffer, data, length);
		}
	}

	free(key);
	free(header);
	free(debug);

	return ret;
}

uint32_t __stdcall warden_config(uint32_t instance, uint32_t config_bit, uint8_t enabled){
	warden_instance *ctx = (warden_instance*)instance;
	switch(config_bit){
		case CONFIG_SAVE_CHECKS:    ctx->config = (enabled == 1 ? ctx->config | CONFIG_SAVE_CHECKS    : ctx->config & ~CONFIG_SAVE_CHECKS);    break;
		case CONFIG_SAVE_UNKNOWN:   ctx->config = (enabled == 1 ? ctx->config | CONFIG_SAVE_UNKNOWN   : ctx->config & ~CONFIG_SAVE_UNKNOWN);   break;
		case CONFIG_LOG_CHECKS:     ctx->config = (enabled == 1 ? ctx->config | CONFIG_LOG_CHECKS     : ctx->config & ~CONFIG_LOG_CHECKS);     break;
		case CONFIG_LOG_PACKETS:    ctx->config = (enabled == 1 ? ctx->config | CONFIG_LOG_PACKETS    : ctx->config & ~CONFIG_LOG_PACKETS);    break;
		case CONFIG_DEBUG_MODE:     ctx->config = (enabled == 1 ? ctx->config | CONFIG_DEBUG_MODE     : ctx->config & ~CONFIG_DEBUG_MODE);     break;
		case CONFIG_USE_GAME_FILES: ctx->config = (enabled == 1 ? ctx->config | CONFIG_USE_GAME_FILES : ctx->config & ~CONFIG_USE_GAME_FILES); break;
		default:
			ctx->config = config_bit;
	}
	return 1;
}

uint32_t __stdcall warden_set_data_file(uint32_t instance, uint8_t *file, uint32_t length){
	warden_instance *ctx = (warden_instance*)instance;
	if(length > 0){
		ctx->data_file = safe_malloc(length+1);
		memcpy(ctx->data_file, file, length);
		return 1;
	}else{
		if(ctx->data_file != NULL)
			free(ctx->data_file);
		return 0;
	}
}

uint8_t *warden_read_game_file(warden_instance *ctx, uint8_t *library, uint32_t address, uint8_t length, uint8_t *header, uint8_t *key, uint32_t adjustment){
	
	uint8_t *file_header = safe_malloc(16);
	uint32_t ret = 0;
	uint32_t lib_addr;
	uint8_t *lib_path;
	uint8_t *data = safe_malloc(0x100);


	if(ctx->product == 'WAR3' || ctx->product == 'W3XP')
		sprintf_s(file_header, 16, "Files_WAR3");
	else if(ctx->product == 'STAR' || ctx->product == 'SEXP')
		sprintf_s(file_header, 16, "Files_STAR");
	else if(ctx->product == 'D2DV')
		sprintf_s(file_header, 16, "Files_D2DV");
	else if(ctx->product == 'D2XP')
		sprintf_s(file_header, 16, "Files_D2XP");
	else
		ret = 1;

	if(ret == 1){
		free(file_header);
		free(data);
		return NULL;
	}

	lib_path = read_ini((ctx->data_file != NULL ? ctx->data_file : "Warden.ini"), file_header, library, NULL);

	if(lib_path == NULL){
		sprintf_s(data, 0x100, "Could not find path for: %s -> %s\n", file_header, library);
		write_to_file(data);
		free(file_header);
		free(data);
		return NULL;
	}

	lib_addr = (uint32_t)LoadLibrary(lib_path);

	if(lib_addr == 0){
		sprintf_s(data, 0x100, "Could not load library: %s\n", lib_path);
		write_to_file(data);
		free(file_header);
		free(data);
		return NULL;
	}

	memcpy(data, (uint8_t*)(address - adjustment + lib_addr), length);

	if(write_ini((ctx->data_file != NULL ? ctx->data_file : "Warden.ini"), header, key, to_hex(data, length, FALSE)) == 0){
		sprintf_s(data, 0x100, "Could not read %d bytes @ 0x%08X from %s\n", length, address, library);
		write_to_file(data);
		free(file_header);
		free(data);
		FreeLibrary((HMODULE)lib_addr);
		return NULL;
	}else{
		FreeLibrary((HMODULE)lib_addr);
		return data;
	}
}