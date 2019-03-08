#include "crevold.h"
/*void wwrite_to_file(const uint8_t *data){
	FILE *fp;
	fopen_s(&fp, "WardenLog.txt", "a");
	fwrite(data, 1, strlen(data), fp);
	fclose(fp);
}*/

uint32_t __stdcall crev_ver1(uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, uint8_t *ini_file, uint8_t *ini_header, uint32_t *version, uint32_t *checksum, uint8_t *result){
	return crev_old(0, archive_name[7] - '0', seed, ini_file, ini_header, version, checksum, result);
}

uint32_t __stdcall crev_ver2(uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, uint8_t *ini_file, uint8_t *ini_header, uint32_t *version, uint32_t *checksum, uint8_t *result){
	return crev_old(1, archive_name[9] - '0', seed, ini_file, ini_header, version, checksum, result);
}

uint32_t __stdcall crev_old(uint32_t padd, uint8_t archive_ver, uint8_t *seed, uint8_t *ini_file, uint8_t *ini_header, uint32_t *version, uint32_t *checksum, uint8_t *result){
	uint64_t A = 0;
	uint64_t B = 0;
	uint64_t C = 0;
	uint32_t S = 0;
	uint32_t x = 0;
	uint32_t y = 0;
	uint32_t file_size = 0;
	uint8_t  ops[4];
	uint8_t *files[4];
	uint8_t *buff = safe_malloc(MAX_PATH);
	const uint8_t *keys[] = {"Exe", "Util", "Network"};
	const uint32_t seeds[] = {0xE7F4CB62, 0xF6A14FFC, 0xAA5504AF, 0x871FCDC2, 0x11BF6A18, 0xC57292E6, 0x7927D27E, 0x2FEC8733};

	uint8_t *tok;
	uint8_t *tok_pos;
	//uint8_t *tmp = safe_malloc(MAX_PATH * 2);

	if(archive_ver > 7){
		free(buff);
		return CREV_UNKNOWN_REVISION;
	}

	tok = strtok_s(seed, " ", &tok_pos);
	for(x = 0; x < 3; x++){
		if(tok == NULL)
			return CREV_MALFORMED_SEED;
		if(tok[1] == '='){
			if(tok[0] == 'A' || tok[0] == 'a') A = strtoul((uint8_t*)&tok[2], NULL, 10);
			if(tok[0] == 'B' || tok[0] == 'b') B = strtoul((uint8_t*)&tok[2], NULL, 10);
			if(tok[0] == 'C' || tok[0] == 'c') C = strtoul((uint8_t*)&tok[2], NULL, 10);
		}else{
			return CREV_MALFORMED_SEED;
		}
		tok = strtok_s(NULL, " ", &tok_pos);
	}
	/*
	 *sprintf_s(tmp, MAX_PATH * 2, "A: %lu\n", A); wwrite_to_file(tmp);
	 *sprintf_s(tmp, MAX_PATH * 2, "B: %lu\n", B); wwrite_to_file(tmp);
	 *sprintf_s(tmp, MAX_PATH * 2, "C: %lu\n", C); wwrite_to_file(tmp);
	 */
	
	tok = strtok_s(NULL, " ", &tok_pos); //Skip the '4'

	for(x = 0; x < 4; x++){
		if(tok == NULL)
			return CREV_MALFORMED_SEED;
		ops[x] = tok[3];
		tok[3] = '.';
		switch(x){
			case 0: if(_stricmp(tok, "A=A.S") != 0) return CREV_MALFORMED_SEED; break;
			case 1: if(_stricmp(tok, "B=B.C") != 0) return CREV_MALFORMED_SEED; break;
			case 2: if(_stricmp(tok, "C=C.A") != 0) return CREV_MALFORMED_SEED; break;
			case 3: if(_stricmp(tok, "A=A.B") != 0) return CREV_MALFORMED_SEED; break;
		}
		tok = strtok_s(NULL, " ", &tok_pos);
	}

	//sprintf_s(tmp, MAX_PATH * 2, "Ops: %c%c%c%c\n", ops[0], ops[1], ops[2], ops[3]); wwrite_to_file(tmp);

	read_ini_new(ini_file, ini_header, "Path", "", buff, MAX_PATH);
	files[0] = safe_malloc(MAX_PATH);
	combine_paths(buff, "", files[0], MAX_PATH);

	for(x = 1; x < 4; x++){
		read_ini_new(ini_file, ini_header, (uint8_t*)keys[x-1], "\xFF", buff, MAX_PATH);
		if(buff[0] == 0xFF){
			for(y = 0; y < x; y++)
				if(files[y] != NULL) free(files[y]);
			sprintf_s(result, crev_max_result(), "%s\x00", keys[x-1]);
			return CREV_MISSING_FILENAME;
		}

		if (_stricmp(buff, "NULL") == 0){
			files[x] = NULL;
		}else{
			files[x] = safe_malloc(MAX_PATH);
			combine_paths(files[0], buff, files[x], MAX_PATH);
		}
	}
	free(buff);
	/*
	 *sprintf_s(tmp, MAX_PATH * 2, "Path:    %s\n", files[0]); wwrite_to_file(tmp);
	 *sprintf_s(tmp, MAX_PATH * 2, "Exe:     %s %d\n", files[1], get_file_size(files[1])); wwrite_to_file(tmp);
	 *sprintf_s(tmp, MAX_PATH * 2, "Util:    %s %d\n", files[2], get_file_size(files[2])); wwrite_to_file(tmp);
	 *sprintf_s(tmp, MAX_PATH * 2, "Network: %s %d\n", files[3], get_file_size(files[3])); wwrite_to_file(tmp);
	 */

	A ^= seeds[archive_ver];
	for(x = 1; x < 4; x++){
		if (files[x] == NULL){
			continue;
		}
		file_size = get_file_size(files[x]);
		if((file_size % 1024) != 0){
			if(padd == 1) file_size += (1024 - (file_size % 1024));
			else          file_size -= (file_size % 1024);
		}

		if(file_size == 0){
			sprintf_s(result, CREV_MAX_RESULT, files[x]);
			return CREV_MISSING_FILE;
		}

		buff = safe_malloc(file_size);
		get_file_data(files[x], buff, file_size, padd);

		for(y = 0; y < file_size; y+= 4){
			S = (*(uint32_t*)&buff[y]);
		    switch (ops[0]) {
                case '^': A ^= S; break;
                case '+': A += S; break;
                case '-': A -= S; break;
                case '*': A *= S; break;
                case '/': A /= S; break;
            }
            switch (ops[1]){
                case '^': B ^= C; break;
                case '+': B += C; break;
                case '-': B -= C; break;
                case '*': B *= C; break;
                case '/': B /= C; break;
            }
            switch (ops[2]){
                case '^': C ^= A; break;
                case '+': C += A; break;
                case '-': C -= A; break;
                case '*': C *= A; break;
                case '/': C /= A; break;
            }
            switch (ops[3]){
                case '^': A ^= B; break;
                case '+': A += B; break;
                case '-': A -= B; break;
                case '*': A *= B; break;
                case '/': A /= B; break;
            }
		}
		free(buff);
	}
	*checksum = (uint32_t)(C & 0x00000000FFFFFFFF);
	*version = crev_get_file_version(files[1]);
	S = crev_get_file_information(files[1], result, CREV_MAX_RESULT);

	for(x = 0; x < 4; x++){
		if(files[x] != NULL)
			free(files[x]);
	}

	return S;
}

uint32_t crev_get_file_information(uint8_t *file, uint8_t *buffer, uint32_t size){
	uint8_t   *file_name;
	uint32_t   x = 0;
	uint32_t   len = 0;
	FILETIME   ft;
	SYSTEMTIME st;
	HANDLE     fhandle;

	sprintf_s(buffer, size, file);

	len = strlen(file);
	if(len == 0) return CREV_FILE_INFO_ERROR;

	file_name = safe_malloc(len);
	for(x = len; x != 0; x--){
		if(file[x] == '\\' || file[x] == '/')
			break;
	}
	memcpy(file_name, (uint8_t*)(&file[x+1]), len - x + 1);

	fhandle = CreateFile(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if(fhandle == INVALID_HANDLE_VALUE){
		free(file_name);
		return CREV_FILE_INFO_ERROR;
	}

	if(GetFileTime(fhandle, NULL, &ft, NULL) == 0){
		free(file_name);
		CloseHandle(fhandle);
		return CREV_FILE_INFO_ERROR;
	}
	len = GetFileSize(fhandle, NULL);
	CloseHandle(fhandle);

	if(FileTimeToSystemTime(&ft, &st) == 0){
		free(file_name);
		return CREV_FILE_INFO_ERROR;
	}

	sprintf_s(buffer, size, "%s %02u/%02u/%02u %02u:%02u:%02u %lu",
		file_name, st.wMonth, st.wDay, (st.wYear % 100), st.wHour, st.wMinute, st.wSecond, len);

	free(file_name);
	return CREV_SUCCESS;
}