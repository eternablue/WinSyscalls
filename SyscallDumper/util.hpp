#include <stdio.h>
#include <Windows.h>
#include <stdint.h>

uint32_t LittletoBigEndian(uint8_t bytes[4])
{
	return (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
}

uint32_t get_syscall_id_by_name(const char* api_name)
{
	uint64_t base = (uint64_t)GetModuleHandleA("ntdll");
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(base + dos_header->e_lfanew);

	IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + nt_header->OptionalHeader.DataDirectory[0].VirtualAddress);

	uint32_t* name_rva = (uint32_t*)(base + exports->AddressOfNames);

	for (uint32_t i = 0; i < exports->NumberOfNames; ++i)
	{
		uint32_t* function = (uint32_t*)(base + exports->AddressOfFunctions);
		uint16_t* ordinal = (uint16_t*)(base + exports->AddressOfNameOrdinals);
		uint64_t address = (uint64_t)base + function[ordinal[i]];

		if (!strcmp((char*)(base + name_rva[i]), api_name))
			return LittletoBigEndian((uint8_t*)(address + 4));
	}
}