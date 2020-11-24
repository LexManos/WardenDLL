// Test.cpp : Defines the entry point for the console application.
//
#include "test.h"


int main()
{
	testW2BN();

	getchar();
	return 0;
}

void testW2BN()
{
	uint8_t seed[] = { 0x07, 0x0C, 0xB5, 0x34, 0x31, 0x8A, 0xC3, 0x61, 0xD0, 0x7D, 0x40, 0x74, 0xB5, 0xD2, 0x75, 0x0B, 0x00 };
	uint32_t version = 0;
	uint32_t checksum = 0;
	uint8_t *result = malloc(crev_max_result());
	uint32_t ret = 0;
	int x = 0;

	ret = check_revision("1234", "lockdown-IX86-00.mpq", seed, "..\\CheckRevision.ini", "CRev_W2", &version, &checksum, result);
	printf("Seed:     "); printHexNull(seed, 0x20); printf("\n");
	printf("Version:  %08x\n", version);
	printf("Checksum: %08x\n", checksum);
	printf("Result:   "); printHexNull(result, crev_max_result()); printf("\n");
}

void printHex(uint8_t *data, int length)
{
	int x = 0;
	while (x < length)
		printf("%02x", data[x++]);
}
void printHexNull(uint8_t *data, int length)
{
	int x = 0;
	while (data[x] != 0 && x < length)
		printf("%02x", data[x++]);
}

