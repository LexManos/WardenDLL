#include "log.h"

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