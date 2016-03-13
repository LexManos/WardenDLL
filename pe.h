#ifndef _PE_H_
#define _PE_H_

#include "types.h"
#include "stdint.h"
#include "crev.h"

#define PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES (16)
typedef struct PE_IMAGE_DATA_DIRECTORY{
	uint32_t VirtualAddress; //: 0x00
	uint32_t Size;           //: 0x04
}PE_IMAGE_DATA_DIRECTORY;

#define PE_DATA_DIRECTORY_IMPORT_TABLE       (1)
#define PE_DATA_DIRECTORY_IMPORT_TABLE_SIZE (0x14)
typedef struct PE_DATA_DIRECTORY_IMPORT{
	uint32_t ImportLookupRVA;  //: 0x00
	uint32_t TimeDateStamp;    //: 0x04
	uint32_t ForwarderChain;   //: 0x08
	uint32_t NameRVA;          //: 0x0C
	uint32_t ImportAddressRVA; //: 0x10
}PE_DATA_DIRECTORY_IMPORT;

#define PE_DATA_DIRECTORY_RELOC_TABLE       (5)
typedef struct PE_DATA_DIRECTORY_RELOC{
	uint32_t RVA;  //: 0x00
	uint32_t Size; //: 0x04
}PE_DATA_DIRECTORY_RELOC;

#define PE_IMAGE_FILE_MACHINE_I386 (0x014C) 
#define PE_IMAGE_SIZEOF_FILE_HEADER (20)
typedef struct PE_IMAGE_FILE_HEADER{   
	uint16_t Machine;              //: 0x00
	uint16_t NumberOfSections;     //: 0x02
	uint32_t TimeDateStamp;        //: 0x04
	uint32_t PointerToSymbolTable; //: 0x08
	uint32_t NumberOfSymbols;      //: 0x0c
	uint16_t SizeOfOptionalHeader; //: 0x10
	uint16_t Characteristics;      //: 0x12
}PE_IMAGE_FILE_HEADER;

#define PE_IMAGE_NT_OPTIONAL_HDR32_MAGIC (0x10b)
typedef struct PE_IMAGE_OPTIONAL_HEADER32{                                       
  // Standard fields.                                                         
  uint16_t Magic;                                                             //: 0x00
  uint8_t  MajorLinkerVersion;                                                //: 0x02
  uint8_t  MinorLinkerVersion;                                                //: 0x03
  uint32_t SizeOfCode;                                                        //: 0x04
  uint32_t SizeOfInitializedData;                                             //: 0x08
  uint32_t SizeOfUninitializedData;                                           //: 0x0c
  uint32_t AddressOfEntryPoint;                                               //: 0x10
  uint32_t BaseOfCode;                                                        //: 0x14
  uint32_t BaseOfData;                                                        //: 0x18
  // NT additional fields.                                                    
  uint32_t ImageBase;                                                         //: 0x1c
  uint32_t SectionAlignment;                                                  //: 0x20
  uint32_t FileAlignment;                                                     //: 0x24
  uint16_t MajorOperatingSystemVersion;                                       //: 0x28
  uint16_t MinorOperatingSystemVersion;                                       //: 0x2a
  uint16_t MajorImageVersion;                                                 //: 0x2c
  uint16_t MinorImageVersion;                                                 //: 0x2e
  uint16_t MajorSubsystemVersion;                                             //: 0x30
  uint16_t MinorSubsystemVersion;                                             //: 0x32
  uint32_t Win32VersionValue;                                                 //: 0x34
  uint32_t SizeOfImage;                                                       //: 0x38
  uint32_t SizeOfHeaders;                                                     //: 0x3c
  uint32_t CheckSum;                                                          //: 0x40
  uint16_t Subsystem;                                                         //: 0x44
  uint16_t DllCharacteristics;                                                //: 0x46
  uint32_t SizeOfStackReserve;                                                //: 0x48
  uint32_t SizeOfStackCommit;                                                 //: 0x4c
  uint32_t SizeOfHeapReserve;                                                 //: 0x50
  uint32_t SizeOfHeapCommit;                                                  //: 0x54
  uint32_t LoaderFlags;                                                       //: 0x58
  uint32_t NumberOfRvaAndSizes;                                               //: 0x5c
  PE_IMAGE_DATA_DIRECTORY DataDirectory[PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; //: 0x60
}PE_IMAGE_OPTIONAL_HEADER32;

#define PE_SIZE_OF_NT_SIGNATURE (4)
#define PE_NT_HEADER_SIGNATURE_PE (0x00004550) //PE\x00\x00
typedef struct PE_IMAGE_NT_HEADERS{
  uint32_t Signature;                        //: 0x00
  PE_IMAGE_FILE_HEADER FileHeader;           //: 0x04
  PE_IMAGE_OPTIONAL_HEADER32 OptionalHeader; //: 0x18
}PE_IMAGE_NT_HEADERS;

#define DOS_HEADER_MAGIC (0x5A4D) //MZ
typedef struct PE_IMAGE_DOS_HEADER{ //DOS .EXE Header
	uint16_t e_magic;         // Magic number                      : 0x00
	uint16_t e_cblp;          // Bytes on last page of file        : 0x02
	uint16_t e_cp;            // Pages in file                     : 0x04
	uint16_t e_crlc;          // Relocations                       : 0x06
	uint16_t e_cparhdr;       // Size of header in paragraphs      : 0x08
	uint16_t e_minalloc;      // Minimum extra paragraphs needed   : 0x0a
	uint16_t e_maxalloc;      // Maximum extra paragraphs needed   : 0x0c
	uint16_t e_ss;            // Initial (relative) SS value       : 0x0e
	uint16_t e_sp;            // Initial SP value                  : 0x10
	uint16_t e_csum;          // Checksum                          : 0x12
	uint16_t e_ip;            // Initial IP value                  : 0x14
	uint16_t e_cs;            // Initial (relative) CS value       : 0x16
	uint16_t e_lfarlc;        // File address of relocation table  : 0x18
	uint16_t e_ovno;          // Overlay number                    : 0x1a
	uint16_t e_res[4];        // Reserved words                    : 0x1c
	uint16_t e_oemid;         // OEM identifier (for e_oeminfo)    : 0x24
	uint16_t e_oeminfo;       // OEM information; e_oemid specific : 0x26
	uint16_t e_res2[10];      // Reserved words                    : 0x28
	uint32_t e_lfanew;        // File address of new exe header    : 0x3c
}PE_IMAGE_DOS_HEADER;

#define PE_IMAGE_SIZEOF_SHORT_NAME (8)
#define PE_IMAGE_SIZEOF_SECTION_HEADER (40)
#define PE_IMAGE_SECTION_CHR_MEM_WRITE (0x80000000)
typedef struct PE_IMAGE_SECTION_HEADER{
	uint8_t Name[IMAGE_SIZEOF_SHORT_NAME]; //: 0x00
	union {                              
		uint32_t PhysicalAddress;        
		uint32_t VirtualSize;            
	} Misc;                                //: 0x04
	uint32_t VirtualAddress;               //: 0x08
	uint32_t SizeOfRawData;                //: 0x0c
	uint32_t PointerToRawData;             //: 0x10
	uint32_t PointerToRelocations;         //: 0x14
	uint32_t PointerToLinenumbers;         //: 0x18
	uint16_t NumberOfRelocations;          //: 0x20
	uint16_t NumberOfLinenumbers;          //: 0x24
	uint32_t Characteristics;              //: 0x28
}PE_IMAGE_SECTION_HEADER;

uint32_t pe_load_library(uint8_t *file_path);
uint32_t pe_unload_library(uint32_t file);

#endif