#include "config.h"

uint8_t *read_ini(const uint8_t *file, uint8_t *header, uint8_t *key, uint8_t *defa){
	uint8_t *path = safe_malloc(MAX_PATH);
	uint8_t *buff = safe_malloc(MAX_PATH);
	uint32_t lret;
	uint32_t x;

	if(strstr(file, ":\\") == NULL){
		lret = GetModuleFileName(NULL, path, MAX_PATH);

		for(x = lret; x > 0; x--){ //Strip out the EXE name
			if(path[x] == '\\' || path[x] == '/'){
				path[x] = 0;
				break;
			}
		}

		sprintf_s(path, MAX_PATH, "%s\\%s", path, file);
		lret = GetPrivateProfileStringA(header, key, defa, buff, 0x100, path);
	}else{
		lret = GetPrivateProfileStringA(header, key, defa, buff, 0x100, file);
	}
	free(path);
	return (lret == 0 ? defa : buff);
}

uint32_t read_ini_new(const uint8_t *file, uint8_t *header, uint8_t *key, uint8_t *defa, uint8_t *buff, uint32_t length){
	uint8_t *path = safe_malloc(MAX_PATH);
	uint32_t ret;
	uint32_t x;

	if(strstr(file, ":\\") == NULL){
		ret = GetModuleFileName(NULL, path, MAX_PATH);

		for(x = ret; x > 0; x--){ //Strip out the EXE name
			if(path[x] == '\\' || path[x] == '/'){
				path[x] = 0;
				break;
			}
		}

		sprintf_s(path, 0x400, "%s\\%s", path, file);
		ret = GetPrivateProfileStringA(header, key, defa, buff, length, path);
	}else{
		ret = GetPrivateProfileStringA(header, key, defa, buff, length, file);
	}
	free(path);
	return ret;
}
uint32_t write_ini(const uint8_t *file, uint8_t *header, uint8_t *key, uint8_t *data){
	uint8_t *path = safe_malloc(0x400);
	uint32_t ret;
	if(strstr(file, ":\\") == NULL){
		GetCurrentDirectory(0x400, path);
		sprintf_s(path, 0x400, "%s\\%s", path, file);
		ret = WritePrivateProfileStringA(header, key, data, path);
	}else{
		ret = WritePrivateProfileStringA(header, key, data, file);
	}
	free(path);
	return ret;
}

