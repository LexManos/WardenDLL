#include "pe.h"

uint32_t pe_load_library(uint8_t *file_path){
	uint32_t                 file_size;
	uint32_t                 sections_offset;
	uint32_t                 x;
	uint8_t                 *file_data;
	uint8_t                 *mapped_data;
	PE_IMAGE_DOS_HEADER     *dos;
	PE_IMAGE_NT_HEADERS     *nt;
	PE_IMAGE_SECTION_HEADER *sections;

	file_size = get_file_size(file_path);
	if(file_size == 0) return 0;

	file_data = safe_malloc(file_size);
	if(get_file_data(file_path, file_data, file_size, 0) == 1){
		free(file_data);
		return 0;
	}

	dos = (PE_IMAGE_DOS_HEADER*)file_data;
	if(dos->e_magic != DOS_HEADER_MAGIC){
		free(file_data);
		return 0;
	}

	nt = (PE_IMAGE_NT_HEADERS*)(file_data + dos->e_lfanew);
	if(nt->Signature != PE_NT_HEADER_SIGNATURE_PE){
		free(file_data);
		return 0;
	}

	if(nt->OptionalHeader.Magic != PE_IMAGE_NT_OPTIONAL_HDR32_MAGIC){
		free(file_data);
		return 0;
	}

	if(nt->FileHeader.NumberOfSections == 0){
		free(file_data);
		return 0;
	}
	sections_offset = nt->FileHeader.SizeOfOptionalHeader + dos->e_lfanew + PE_SIZE_OF_NT_SIGNATURE + PE_IMAGE_SIZEOF_FILE_HEADER;
	sections = (PE_IMAGE_SECTION_HEADER *)(file_data + sections_offset);

	file_size = sections[nt->FileHeader.NumberOfSections - 1].VirtualAddress 
			  + sections[nt->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
	if((file_size % nt->OptionalHeader.SectionAlignment) != 0)
		file_size += nt->OptionalHeader.SectionAlignment - (file_size % nt->OptionalHeader.SectionAlignment);

	//Allocate new memory and copy PE headers over.
	mapped_data = safe_malloc(file_size);
	memcpy(mapped_data, file_data, sections_offset + (PE_IMAGE_SIZEOF_SECTION_HEADER * nt->FileHeader.NumberOfSections));

	dos = (PE_IMAGE_DOS_HEADER*)mapped_data;
	nt  = (PE_IMAGE_NT_HEADERS*)(mapped_data + dos->e_lfanew);
	sections = (PE_IMAGE_SECTION_HEADER *)(mapped_data + sections_offset);
	for(x = 0; x < nt->FileHeader.NumberOfSections; x++){
		//Copy sections over
		memset(mapped_data + sections[x].VirtualAddress, 0, sections[x].Misc.VirtualSize); 
		memcpy(mapped_data + sections[x].VirtualAddress, file_data + sections[x].PointerToRawData, 
			(sections[x].SizeOfRawData > sections[x].Misc.VirtualSize ? 
			 sections[x].Misc.VirtualSize : sections[x].SizeOfRawData));
	}

	free(file_data);    

	return (uint32_t)mapped_data;
}

uint32_t pe_unload_library(uint32_t file){
	if(file != 0) free((uint8_t*)file);
	return 0;
}