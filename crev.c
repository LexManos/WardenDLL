#include "crev.h"

uint32_t __stdcall crev_max_result(){
	return CREV_MAX_RESULT;
}

uint32_t __stdcall check_revision(uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, 
								  uint8_t *ini_file, uint8_t *ini_header, 
								  uint32_t *version, uint32_t *checksum, uint8_t *result){
	uint32_t lret = CREV_SUCCESS;

	switch(strlen(archive_name)){
		case 12: lret = crev_ver1(archive_time, archive_name, seed, ini_file, ini_header, version, checksum, result); break;
		case 14: lret = crev_ver2(archive_time, archive_name, seed, ini_file, ini_header, version, checksum, result); break;
		case 20:
			if(strstr(archive_name, "lockdown") != NULL)
				lret = crev_ver3(archive_time, archive_name, seed, ini_file, ini_header, version, checksum, result); 
			else lret = CREV_UNKNOWN_VERSION;
			break;
		default: lret = CREV_UNKNOWN_VERSION;
	}
	if (strcmp(archive_name, "CheckRevision.mpq") == 0)
		lret = crev_simple(archive_time, archive_name, seed, ini_file, ini_header, version, checksum, result);
	else if (strcmp(archive_name, "CheckRevisionD1.mpq") == 0)
		lret = crev_simple_d1(archive_time, archive_name, seed, ini_file, ini_header, version, checksum, result);

	return lret;
}

uint32_t  __stdcall crev_error_description(uint32_t error, uint8_t *buffer, uint32_t size){
	uint8_t *message;
	switch(error){
		case CREV_SUCCESS:             message = "Success"; break;
		case CREV_UNKNOWN_VERSION:     message = "Unsupported archive version"; break;
		case CREV_UNKNOWN_REVISION:    message = "Unsupported archive sub-version"; break;
		case CREV_MALFORMED_SEED:      message = "Seed value was malformed"; break;
		case CREV_MISSING_FILENAME:    message = "File name missing from INI file"; break;
		case CREV_MISSING_FILE:        message = "Failed to open file"; break;
		case CREV_FILE_INFO_ERROR:     message = "Failed to get executable information"; break;
		case CREV_TOFEW_RVAS:          message = "Less then 14 RVAs in Hash file"; break;
		case CREV_UNKNOWN_RELOC_TYPE:  message = "Encountered Unknown Reloc Table Type"; break;
		case CREV_OUT_OF_MEMORY:       message = "Out of Memory"; break;
		case CREV_CORRUPT_IMPORT_DATA: message = "Currupt Import Address Table Data"; break;
		default:                       message = "Unknown Error Code"; break;
	}
	if(strlen(message) > size) return strlen(message);

	memcpy(buffer, message, strlen(message) + 1);
	return 0;
}

uint32_t crev_get_file_version(uint8_t *file){
	uint32_t info_size;
	uint8_t *data;
	uint32_t version;
	VS_FIXEDFILEINFO *ffi;
	info_size = GetFileVersionInfoSize(file, NULL);

	if(info_size == 0) return 0;
	data = safe_malloc(info_size);

	if(GetFileVersionInfo(file, (DWORD)NULL, info_size, (uint8_t*)data) == 0){
		free(data);
		return 0;
	}

	if(!VerQueryValue(data, "\\", (LPVOID*)&ffi, &info_size)){
		free(data);
		return 0;
	}

	version = ((ffi->dwProductVersionMS & 0x00FF0000) <<  8) |
			  ((ffi->dwProductVersionMS & 0x000000FF) << 16) |
			  ((ffi->dwProductVersionLS & 0x00FF0000) >>  8) |
			  (ffi->dwProductVersionLS & 0x000000FF);
	free(data);
	return version;
}

uint32_t get_file_size(uint8_t *file){
	FILE *fp;
	uint32_t len;

	fopen_s(&fp, file, "r");
	if(fp == NULL) return 0;

	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fclose(fp);
	return len;
}

uint32_t get_file_data(uint8_t *file, uint8_t *data, uint32_t size, uint32_t padd){
	FILE *fp;
	uint32_t lret;
	uint32_t x = 0;
	uint8_t  b_pad = 0xFF;

	fopen_s(&fp, file, "rb");
	if(fp == NULL) return 0;

	lret = fread(data, 1, size, fp);
	if(lret != size){
		if((padd == 1) && (feof(fp) != 0)){
			for(x = lret; x < size; x++)
				data[x] = b_pad--;
		}else{
			return 1;
		}
	}

	fclose(fp);
	return 0;
}

void combine_paths(uint8_t *folder, uint8_t *file, uint8_t *buff, uint32_t size){
	uint32_t lret;
	uint32_t x;
	uint32_t fLen;
	uint8_t *directory = safe_malloc(MAX_PATH);

	directory[0] = 0;
	if(strstr(folder, ":\\") == NULL){
		lret = GetModuleFileName(NULL, directory, MAX_PATH); //Get App.Path

		for(x = lret; x > 0; x--){ //Strip out the EXE name
			if(directory[x] == '\\' || directory[x] == '/'){
				directory[x] = 0;
				break;
			}
		}
	}

	if(folder[0] == '\\' || folder[0] == '/') folder++; //Remove leading \ or /
	fLen = strlen(folder);
	if(fLen > 0 && (folder[fLen - 1] == '\\' || folder[fLen - 1] == '/')) folder[fLen - 1] = 0; //Remove Trailing / or \


	if(directory[0] != 0)
		sprintf_s(buff, size, "%s\\%s\\%s", directory, folder, (file == NULL ? '\x00' : file));
	else
		sprintf_s(buff, size, "%s\\%s", folder, (file == NULL ? '\x00' : file));

	free(directory);
}