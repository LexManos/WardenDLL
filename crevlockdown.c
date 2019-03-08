#include "crevlockdown.h"
/*void wwrite_to_file(const uint8_t *data){
	FILE *fp;
	fopen_s(&fp, "C:\\WardenLog.txt", "a");
	MessageBox(0, data, "", 0);
	fwrite(data, 1, strlen(data), fp);
	fclose(fp);
}
uint8_t *tto_hex(uint8_t *data, uint32_t size, BOOLEAN spaces){
	uint8_t *buff = safe_malloc(size * (spaces == TRUE ? 3 : 2));
	uint32_t x = 0;
	
	for(x = 0; x < size; x++){
		if(spaces == TRUE)
			sprintf_s((uint8_t*)(buff + (3 * x)), 4, "%02X ", data[x]);
		else
			sprintf_s((uint8_t*)(buff + (2 * x)), 4, "%02X", data[x]);
	}
	return buff;
}*/

uint32_t __stdcall crev_ver3(uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, uint8_t *ini_file, uint8_t *ini_header, uint32_t *version, uint32_t *checksum, uint8_t *result){
	uint32_t                 x = 0;
	uint32_t                 y = 0;
	uint32_t                 z = 0;
	uint32_t                 lret;
	uint8_t                 *files[5];
	//uint8_t                 *tok;
	uint8_t                 *buff;
	uint8_t                 *buff2;
	uint32_t                 archive_rev = 0;
	uint32_t                 header_size = 0;
	sha1_context             sha;
	lockdown_heep            ldh;
	uint32_t                 pe_file;
	PE_IMAGE_NT_HEADERS     *nt;
	PE_IMAGE_SECTION_HEADER *sections;

	const uint8_t *keys[] = {"Exe", "Util", "Network", "Screen"};
	const uint32_t seeds[] = {
		0xA1F3055A, 0x5657124C, 0x1780AB47, 0x80B3A410, 0xAF2179EA, 
		0x0837B808, 0x6F2516C6, 0xE3178148, 0x0FCF90B6, 0xF2F09516, 
		0x378D8D8C, 0x07F8E083, 0xB0EE9741, 0x7923C9AF, 0xCA11A05E, 
		0xD723C016, 0xFD545590, 0xFB600C2E, 0x684C8785, 0x58BEDE0B
	};
	sha.version = lSHA1;
	sha1_reset(&sha);
	
	if( (archive_name[14] < '0' || archive_name[14] > '1') ||
		(archive_name[15] < '0' || archive_name[15] > '9')){
		return CREV_UNKNOWN_REVISION;
	}

	archive_rev = ((archive_name[14] - '0') * 10) +
				   (archive_name[15] - '0');

	buff = safe_malloc(MAX_PATH);
	read_ini_new(ini_file, ini_header, "Path", "", buff, MAX_PATH);
	files[0] = safe_malloc(MAX_PATH);
	
	combine_paths(buff, "", files[0], MAX_PATH);

	for(x = 1; x < 5; x++){
		read_ini_new(ini_file, ini_header, (uint8_t*)keys[x-1], "\xFF", buff, MAX_PATH);
		if(buff[0] == 0xFF){
			for(y = 0; y < x; y++)
				if(files[y] != NULL) free(files[y]);
			sprintf_s(result, crev_max_result(), "%s\x00", keys[x-1]);
			free(buff);
			return CREV_MISSING_FILENAME;
		}
		if (_stricmp(buff, "NULL") == 0){
			files[x] = NULL;
		}else{
			files[x] = safe_malloc(MAX_PATH);
			combine_paths(files[0], buff, files[x], MAX_PATH);
		}
	}

	read_ini_new(ini_file, "CRev_Main", "LockdownPath", "", buff, MAX_PATH);

	combine_paths(buff, "", files[0], MAX_PATH);
	sprintf_s(files[0], MAX_PATH, "%s\\Lockdown-IX86-%02d.dll", files[0], archive_rev);
	free(buff);

	lockdown_shuffle_seed(seed);

	buff = safe_malloc(0x40);
	memset(buff, '6', 0x40);

	for(x = 0; x < 0x10; x++)
		buff[x] ^= seed[x];
	sha1_input(&sha, buff, 0x40);
	free(buff);

	for(x = 0; x < 4; x++){
		if (files[x] == NULL)
			continue;
		pe_file = pe_load_library(files[x]);
		if(pe_file == 0){
			sprintf_s(result, CREV_MAX_RESULT, files[x]);
			for(z = 0; z < 5; z++) if(files[z] != NULL) free(files[z]);
			return CREV_MISSING_FILE;
		}
		nt = (PE_IMAGE_NT_HEADERS*)(pe_file + ((PE_IMAGE_DOS_HEADER*)pe_file)->e_lfanew);
		if(nt->OptionalHeader.NumberOfRvaAndSizes <= 0x0D){
			for(z = 0; z < 5; z++) if(files[z] != NULL) free(files[z]);
			pe_unload_library(pe_file);
			return CREV_TOFEW_RVAS;
		}

		header_size = nt->OptionalHeader.SizeOfHeaders;
		if((header_size % nt->OptionalHeader.FileAlignment) != 0)
			header_size += (nt->OptionalHeader.FileAlignment - (header_size % nt->OptionalHeader.FileAlignment));

		sha1_input(&sha, (uint8_t*)pe_file, header_size); //Hash the PE Header

		
		lockdown_heep_create(&ldh);

		lret = lockdown_proc_reloc(pe_file, &ldh);
		if(lret != CREV_SUCCESS){
			sprintf_s(result, CREV_MAX_RESULT, files[x]);
			for(z = 0; z < 5; z++) if(files[z] != NULL) free(files[z]);
			pe_unload_library(pe_file);
			return lret;
		}

		lret = lockdown_proc_import(pe_file, &ldh);
		if(lret != CREV_SUCCESS){
			sprintf_s(result, CREV_MAX_RESULT, files[x]);
			for(z = 0; z < 5; z++) if(files[z] != NULL) free(files[z]);
			pe_unload_library(pe_file);
			return lret;
		}


		lockdown_heep_sort(&ldh);
		/*for(y = 0; y < ldh.cur_len; y += 0x10){
			wwrite_to_file(tto_hex((uint8_t*)(ldh.mem + y), 16, FALSE)); 
			wwrite_to_file("\n");
		}*/

		sections = (PE_IMAGE_SECTION_HEADER *)(pe_file + nt->FileHeader.SizeOfOptionalHeader + ((PE_IMAGE_DOS_HEADER*)pe_file)->e_lfanew + PE_SIZE_OF_NT_SIGNATURE + PE_IMAGE_SIZEOF_FILE_HEADER);

		for(y = 0; y < nt->FileHeader.NumberOfSections; y++){
			lret = lockdown_hash1(&sha, &ldh, (uint32_t)(&sections[y]), pe_file, seeds[archive_rev]);
			if(lret != CREV_SUCCESS){
				sprintf_s(result, CREV_MAX_RESULT, files[x]);
				for(z = 0; z < 5; z++) if(files[z] != NULL) free(files[z]);
				pe_unload_library(pe_file);
				return lret;
			}
		}

		lockdown_heep_cleanup(&ldh);
		pe_unload_library(pe_file);
	}

	//Hash Screen Buffer
	x = get_file_size(files[4]);
	if(x == 0){
		sprintf_s(result, CREV_MAX_RESULT, files[4]);
		return CREV_MISSING_FILE;
	}
	buff = safe_malloc(x);
	get_file_data(files[4], buff, x, 0);
	sha1_input(&sha, buff, x);
	free(buff);

	sha1_input(&sha, "\x01\x00\x00\x00", 4); //Verify Return Address
	sha1_input(&sha, "\x00\x00\x00\x00", 4); //Verify Module Offset
	buff2 = safe_malloc(sha1_hash_size);
	sha1_digest(&sha, buff2);
	//wwrite_to_file(tto_hex(buff2, sha1_hash_size, FALSE)); wwrite_to_file("\n");

	//Second SHA Pass
	buff = safe_malloc(0x40);
	memset(buff, '\\', 0x40);

	for(x = 0; x < 0x10; x++)
		buff[x] ^= seed[x];
	sha1_reset(&sha);
	sha1_input(&sha, buff, 0x40);
	sha1_input(&sha, buff2, sha1_hash_size);
	memset(buff2, 0, sha1_hash_size);
	sha1_digest(&sha, buff2);

	lockdown_shuffle_digest((uint8_t*)(&buff2[4]));

	*version = crev_get_file_version(files[1]);
	*checksum = (*(uint32_t*)&buff2[0]);
	memcpy(result, (uint8_t*)(&buff2[4]), 0x10);
	
	for(x = 0; x < 5; x++) 
		if(files[x] != NULL) free(files[x]);
	return CREV_SUCCESS;
}

uint32_t lockdown_proc_reloc(uint32_t pe_file, lockdown_heep *ctx){
	uint32_t x;
	uint32_t y;
	PE_IMAGE_NT_HEADERS *nt = (PE_IMAGE_NT_HEADERS*)(pe_file + ((PE_IMAGE_DOS_HEADER*)pe_file)->e_lfanew);
	if(nt->OptionalHeader.DataDirectory[PE_DATA_DIRECTORY_RELOC_TABLE].VirtualAddress != 0){
		uint32_t  reloc_start = pe_file + nt->OptionalHeader.DataDirectory[PE_DATA_DIRECTORY_RELOC_TABLE].VirtualAddress;
		uint32_t  reloc_end   = reloc_start + nt->OptionalHeader.DataDirectory[PE_DATA_DIRECTORY_RELOC_TABLE].Size;
		uint32_t *reloc_buff  = (uint32_t*)safe_malloc(0x10);
		while(reloc_start < reloc_end){
			PE_DATA_DIRECTORY_RELOC *reloc = (PE_DATA_DIRECTORY_RELOC*)(reloc_start);
			for(x = 8; x < reloc->Size; x += 2){
				uint16_t reloc_data = *(uint16_t*)(reloc_start + x);
				uint8_t type = (reloc_data & 0xF000) >> 12;  
				if(type != 0){
					uint32_t reloc_size;
					switch(type){
						case 0x0A: reloc_size = 8; break; //64-Bit
						case 0x03: reloc_size = 4; break; //32-Bit
						case 0x02: reloc_size = 2; break; //16-Bit
						default:
							free(reloc_buff);
							return CREV_UNKNOWN_RELOC_TYPE;
					}
					reloc_buff[0] = reloc->RVA + (reloc_data & 0x0FFF);
					reloc_buff[1] = reloc_size;
					reloc_buff[2] = 2;
					reloc_buff[3] = type;
					y = lockdown_heep_add(ctx, (uint8_t*)(&reloc_buff[0]), 0x10);
					if(y != CREV_SUCCESS){
						free(reloc_buff);
						return y;
					}
				}
			}
			reloc_start += reloc->Size;
		}
		free(reloc_buff); 
	}
	return CREV_SUCCESS;
}
uint32_t lockdown_proc_import(uint32_t pe_file, lockdown_heep *ctx){
	uint32_t y;
	PE_IMAGE_NT_HEADERS *nt = (PE_IMAGE_NT_HEADERS*)(pe_file + ((PE_IMAGE_DOS_HEADER*)pe_file)->e_lfanew);
	if(nt->OptionalHeader.DataDirectory[PE_DATA_DIRECTORY_IMPORT_TABLE].VirtualAddress != 0){
		uint32_t  import_start = pe_file + nt->OptionalHeader.DataDirectory[PE_DATA_DIRECTORY_IMPORT_TABLE].VirtualAddress;
		uint32_t  import_end   = import_start + nt->OptionalHeader.DataDirectory[PE_DATA_DIRECTORY_IMPORT_TABLE].Size;
		uint32_t *import_buff = (uint32_t*)safe_malloc(0x20);

		if(nt->OptionalHeader.DataDirectory[PE_DATA_DIRECTORY_IMPORT_TABLE].Size < 0x14){
			free(import_buff);
			return CREV_CORRUPT_IMPORT_DATA;
		}

		while(import_start < import_end){
			PE_DATA_DIRECTORY_IMPORT *import = (PE_DATA_DIRECTORY_IMPORT*)import_start;

			if(import->NameRVA != 0){
				uint32_t *import_address_table = (uint32_t*)(pe_file + import->ImportAddressRVA);
				y = 0;
				while(import_address_table[y] != 0)
					y++;

				import_buff[0] = import->ImportAddressRVA; //Current Import Address RVA
				import_buff[1] = (y+1) * 4;                //Size of Import Address Data
				import_buff[2] = 0;                        //Unknown
				import_buff[3] = import->ImportLookupRVA;  //Current Import Lookup RVA
				//wwrite_to_file(tto_hex((uint8_t*)(&import_buff[0]), 16, FALSE)); wwrite_to_file("\n");
				
				import_buff[4] = import_start - pe_file; //Current Import Directory RVA
				import_buff[5] = 0x14;                   //Import Diretory Size
				import_buff[6] = 1;                      //Unknown
				import_buff[7] = 0;                      //Unknown
				//wwrite_to_file(tto_hex((uint8_t*)(&import_buff[4]), 16, FALSE)); wwrite_to_file("\n");

				y = lockdown_heep_add(ctx, (uint8_t*)(&import_buff[0]), 0x20);
				if(y != CREV_SUCCESS){
					free(import_buff);
					return y;
				}       
			}
			import_start += PE_DATA_DIRECTORY_IMPORT_TABLE_SIZE;
		}
	}
	return CREV_SUCCESS;
}


uint32_t lockdown_hash1(sha1_context *sha, lockdown_heep *ldh, uint32_t section_ptr, uint32_t pe_file, uint32_t seed){
	uint32_t ptr_mem;
	uint32_t section_padding;
	uint32_t section_len;
	uint32_t heap_idx;
	uint32_t i;
	int32_t  s;

	PE_IMAGE_NT_HEADERS     *nt = (PE_IMAGE_NT_HEADERS*)(pe_file + ((PE_IMAGE_DOS_HEADER*)pe_file)->e_lfanew);
	PE_IMAGE_SECTION_HEADER *section = (PE_IMAGE_SECTION_HEADER*)section_ptr;
	uint32_t                 section_align = nt->OptionalHeader.SectionAlignment;
	uint32_t                *heap_int = (uint32_t*)(ldh->mem);
	uint32_t                 heap_len = ldh->cur_len / 0x10;

	//uint8_t *tmp = safe_malloc(0x200);

	section_padding = ((section_align - (section->Misc.VirtualSize % section_align)) % section_align);
	//sprintf_s(tmp, 0x200, "Virtual Size: 0x%08X Alignment: 0x%08X dwBytes: %08X\n", section->Misc.VirtualSize, section_align, section_padding); wwrite_to_file(tmp);
    
	if((section->Characteristics & PE_IMAGE_SECTION_CHR_MEM_WRITE) == PE_IMAGE_SECTION_CHR_MEM_WRITE){
		lockdown_sha1_pad(sha, section_padding + section->Misc.VirtualSize);
		//sprintf_s(tmp, 0x200, "Padding: 0x%08X\n", section_padding + section->Misc.VirtualSize); wwrite_to_file(tmp);
	}else{
		heap_idx = 0;
		if(heap_len > 0){
			for(i = 0; heap_idx < heap_len && heap_int[i] < section->VirtualAddress; i += 4)
				heap_idx++;
		}
		//sprintf_s(tmp, 0x200, "Index: %d\n", heap_idx); wwrite_to_file(tmp);
		if(section->Misc.VirtualSize > 0){
			ptr_mem = section->VirtualAddress;
			while((ptr_mem - section->VirtualAddress) < section->Misc.VirtualSize){
				section_len = section->VirtualAddress - ptr_mem + section->Misc.VirtualSize;
				//sprintf_s(tmp, 0x200, "SLen: %05d ", section_len); wwrite_to_file(tmp);

				s = (int32_t)heap_int[heap_idx * 4];
				//sprintf_s(tmp, 0x200, "EAX: %08X ", s); wwrite_to_file(tmp);
				if(s > 0){
					s -= ptr_mem;
					//sprintf_s(tmp, 0x200, "EAX: %08X ", s); wwrite_to_file(tmp);
					if(s < (int32_t)section_len)
						section_len = s;
				}
				//sprintf_s(tmp, 0x200, "SLen: %05d\n", section_len); wwrite_to_file(tmp);

				if(section_len > 0){
					sha1_input(sha, (uint8_t*)(pe_file + ptr_mem), section_len);
					ptr_mem += section_len;
				}else{
					lockdown_hash2(sha, pe_file, (uint32_t*)(&heap_int[heap_idx * 4]), ptr_mem, seed);
					ptr_mem += heap_int[heap_idx * 4 + 1];
					heap_idx++;
				}
			}	
		}

		if(section_padding != 0){
			uint8_t *buff = safe_malloc(section_padding);
			memset(buff, 0, section_padding);
			i = 0;
			while(i < section_padding){
				s = 0;
				if(heap_idx < heap_len)
					s = heap_int[heap_idx * 4] - section->Misc.VirtualSize - section->VirtualAddress + buff[0];

				section_padding += i;

				if(s > 0){
					s -= *(uint32_t*)(buff + i);
					if(s < (int32_t)section_padding)
						section_padding = s;
				}

				if(section_padding != 0){
					sha1_input(sha, (uint8_t*)(buff + i), section_padding);
					i += section_padding;
				}else{
					lockdown_hash2(sha, pe_file, (uint32_t*)(&heap_int[heap_idx * 4]), (uint32_t)&buff[i], seed);
					heap_idx++;
					i += heap_int[heap_idx * 4 + 4];
				}
			}
			free(buff);
		}
	}

	return CREV_SUCCESS;
}


/*uint32_t lockdown_hash1(sha1_context *sha, lockdown_heep *ldh, uint32_t pe_file, 
		   uint32_t sectionp, uint32_t section_alignment, uint32_t baseaddr, uint32_t seed){
	uint32_t eax, edi;
	uint32_t index, dwBytes, var_20;
	uint32_t var_30[4], var_40[4];
	uint32_t i;
	uint32_t *lockdown_memory = (uint32_t*)ldh->mem; /* Lets us address the memory as an int, which cleans up a lot of code. 
	uint8_t *allocated_memory_base;
	PE_IMAGE_SECTION_HEADER *section = (PE_IMAGE_SECTION_HEADER*)sectionp;

	edi = section->VirtualAddress;
	var_20 = section->VirtualAddress;

	dwBytes = ((section->Misc.VirtualSize + section_alignment - 1) & ~(section_alignment - 1)) - section->Misc.VirtualSize;

	if((section->Characteristics & 0x80000000) != 0){
		lockdown_sha1_pad(sha, dwBytes + section->Misc.VirtualSize);
	}else{
		/* This loop seems to search for the first non-zero block in memory. 
		index = 0;
		if(ldh->cur_len > 0)
			for(i = 0; index < (ldh->cur_len / 0x10) && lockdown_memory[i] < edi; i += 4)
				index++;

		if(section->Misc.VirtualSize > 0){
			uint8_t *starting_memory = (uint8_t*)(edi + baseaddr);
			uint8_t *ptr_memory = (uint8_t*)(edi + baseaddr);
			uint32_t i = 0;
			
			if(section->Misc.VirtualSize > 0){
				uint32_t memory_offset = index * 4;
				
				do{
					uint32_t section_length = starting_memory - ptr_memory + section->Misc.VirtualSize;

					eax = 0;
					if(index < (ldh->cur_len / 0x10))
						eax = (int)(lockdown_memory[memory_offset] + starting_memory - var_20);

					

					if(eax)
					{
						eax = eax - (uint32_t)ptr_memory;

						if(eax < section_length)
							section_length = eax;
					}

					if(section_length){
						sha1_input(sha, (uint8_t*)ptr_memory, section_length);
						ptr_memory += section_length;
					}
					else
					{
						uint32_t heap_buffer[4];

						memcpy(heap_buffer, lockdown_memory + memory_offset, 0x10);

						//lockdown_hash2(baseaddr, preferred_baseaddr, preferred_baseaddr_upper, ctx, heap_buffer, (void*)ptr_memory, lockdown);
						lockdown_hash2(sha, baseaddr, &heap_buffer[0], (uint32_t)ptr_memory, seed);


						ptr_memory = ptr_memory + heap_buffer[1];
						index = index + 1;
						memory_offset += 4;
					}
				} while((uint32_t)(ptr_memory - starting_memory) < (uint32_t)section->Misc.VirtualSize);
			}
		}

		if(dwBytes <= 0)
			return 1;

		allocated_memory_base = (char*) HeapAlloc(GetProcessHeap(), 0, dwBytes);

		RtlFillMemory(allocated_memory_base, dwBytes, 0);
		if(dwBytes > 0)
		{
			uint32_t i = 0;

			/** This loop only runs once in all my test cases, so I'm not positive that the indexing using "i" will 
			 * work (since that's a large modification of how they did it...) 
			do
			{
				eax = 0;

				if(index < (ldh->cur_len / 0x10)){
					memcpy(var_40, ldh->mem + (index * 16), 0x10);

					eax = (int)(var_40[0] - section->Misc.VirtualSize - var_20 + allocated_memory_base);
				}

				dwBytes = dwBytes + i;

				if(eax){
					eax = eax - ((int*)allocated_memory_base)[i / 4];
					if(eax < dwBytes)
						dwBytes = eax;
				}

				if(dwBytes){
					sha1_input(sha, (uint8_t*)(&allocated_memory_base[i]), dwBytes);
					i = i + dwBytes;
				}else{
					memcpy(var_30, ldh->mem + (index * 16), 0x10);

					//hash2(baseaddr, (char*)preferred_baseaddr, preferred_baseaddr_upper, ctx, var_30, (int*)(&allocated_memory_base[i]), lockdown);
					lockdown_hash2(sha, baseaddr, &var_30[0], (uint32_t)&allocated_memory_base[i], seed);
					index = index + 1;
					i += var_30[4];
				}
			} while((uint32_t)i < (uint32_t)dwBytes);
		}
		HeapFree(GetProcessHeap(), 0, (void*) allocated_memory_base);
	}
	return CREV_SUCCESS;
}*/

void lockdown_hash2(sha1_context *ctx, uint32_t pe_file, uint32_t *heep_data, uint32_t ptr_memory, uint32_t seed){
	if(heep_data[2] == 0){
		if(heep_data[3] == 0) lockdown_sha1_pad(ctx, heep_data[1]);
		else sha1_input(ctx, (uint8_t*)(pe_file + heep_data[3]), heep_data[1]);
	}else if(heep_data[2] == 1){
		uint8_t *data = safe_malloc(0x14);
		memset(data, 0, 0x10);
		if(ptr_memory != 0)
			memcpy(data, (uint8_t*)(pe_file + ptr_memory), 0x14);
		sha1_input(ctx, data, 0x14);
	}else if(heep_data[2] == 2){
		if(heep_data[3] == 3){
			uint32_t value = 0;
			if(ptr_memory != 0)
				value = (*(uint32_t*)(pe_file + ptr_memory)) ^ seed;
			
			sha1_input(ctx, (uint8_t*)&value, 4);
		}
	}
}  

uint32_t lockdown_shuffle_seed(uint8_t *seed){
	uint32_t pos = 0;
	uint32_t i   = 0;
	uint32_t len = 0;

	uint8_t  addr    = 0;
	uint8_t  shifter = 0;
	uint8_t  b       = 0;
	uint8_t *buf;

	len = strlen(seed);
	buf = safe_malloc(len);

	while(len != 0){
		shifter = 0;
		for(i = 0; i < pos; i++){
			b = buf[i];
			buf[i] = (byte)(shifter - buf[i]);
			shifter = (byte)((((uint32_t)(b << 8) - b) + shifter) >> 8);
		}

		if(shifter != 0){
			if(pos >= 0x10) return 1;
			buf[pos++] = shifter;
		}

		addr = (uint8_t)(seed[len - 1] - 1);
		for(i = 0; i < pos; i++){
			buf[i] += addr; //buf[i] = (uint8_t)((buf[i] + addr) & 0xFF); 
			addr = ((buf[i] < addr) ? 1 : 0);
		}

		if(addr != 0){
			if(pos >= 0x10) return 2;
			buf[pos++] = addr;
		}
		len--;
	}
	memcpy(seed, buf, pos);
	while(pos < 0x10) seed[pos++] = 0x00;
	return 0;
}
void lockdown_word_shifter(uint16_t *word1, uint16_t *word2){
	uint16_t str2 = *word1;
	uint16_t str1 = *word2;

    str2 = (uint16_t)((((str1 >> 8) + (str1 & 0xFF)) >> 8) + (((str1 >> 8) + (str1 & 0xFF)) & 0xFF));
    str2 = (uint16_t)((str2 & 0xFF00) | (((str2+1) & 0xFF) - (((str2 & 0xFF) != 0xFF) ? 1 : 0)));

    str1 = (uint16_t)(((str1 - str2) & 0xFF) | (((((str1 - str2) >> 8) & 0xFF)+1) > 0 ? 0 : 0x100));
    str1 = (uint16_t)((str1 & 0xFF00) | (-str1 & 0xFF));
    
    *word1 = str2;
	*word2 = str1;
}
uint32_t lockdown_shuffle_digest(uint8_t *digest){
	uint16_t word1;
	uint16_t word2;
	uint16_t x   = 0;
	uint16_t y   = 0;
	uint16_t pos = 0;

	uint8_t *ret = safe_malloc(0x18);
	uint8_t *t = safe_malloc(0x20);
	for(x = 0x10; x > 0; ){
		while( x > 0 && digest[x-1] == 0x00) x--;
		if(x > 0){
			word1 = 0;
			for(y = x - 1; y < x; y--){
				word2 = (word1 << 8) + digest[y];
				lockdown_word_shifter(&word1, &word2);
				digest[y] = (uint8_t)(word2 & 0xFF);
			}
			if( (0x10 - x) >= 0xff) return 1;
			ret[pos++] = (uint8_t)((word1+1) & 0xFF);
		}
    }
	while(pos < 0x10) ret[pos++] = 0;
	memcpy(digest, ret, pos);
	return 0;
}

void lockdown_heep_create(lockdown_heep *ctx){
	ctx->cur_len   = 0;
	ctx->max_len   = 0x1000;
	ctx->mem       = safe_malloc(ctx->max_len);
}
void lockdown_heep_cleanup(lockdown_heep *ctx){
	if(ctx->mem != NULL) free(ctx->mem);
	ctx->cur_len = 0;
	ctx->max_len = 0;
	ctx->mem     = NULL;
}
static int __cdecl lockdown_heep_sortfunc(const void *record1, const void *record2){
        int *a = (uint32_t*) record1;
        int *b = (uint32_t*) record2;

        if(a[0] < b[0])      return -1;
        else if(a[0] > b[0]) return 1;
        return 0;
}
void lockdown_heep_sort(lockdown_heep *ctx){
	qsort(ctx->mem, ctx->cur_len / 0x10, 0x10, lockdown_heep_sortfunc); 
}
uint32_t lockdown_heep_add(lockdown_heep *ctx, uint8_t *data, uint32_t size){
	if(ctx->max_len == 0) lockdown_heep_create(ctx);

	if(ctx->cur_len + size >= ctx->max_len){
		if((ctx->max_len << 1) < ctx->max_len){
			return CREV_OUT_OF_MEMORY;
		}else{
			uint8_t *tmp_data = safe_malloc(ctx->max_len << 1);
			ctx->max_len <<= 1;
			memset(tmp_data, 0, ctx->max_len);
			memcpy(tmp_data, ctx->mem, ctx->cur_len);
			if(ctx->mem != NULL) free(ctx->mem);
			ctx->mem = tmp_data;
		}
	}
	//wwrite_to_file(tto_hex(data, size, FALSE)); wwrite_to_file("\n");
	memcpy(ctx->mem + ctx->cur_len, data, size);
	ctx->cur_len += size;
	return CREV_SUCCESS;
}
uint32_t lockdown_sha1_pad(sha1_context *ctx, uint32_t length){
	uint8_t *padding = safe_malloc(length);
	uint32_t lret;
	memset(padding, 0, length);
	lret = sha1_input(ctx, padding, length);
	free(padding);
	return lret;
}