#include "util.hpp"

/*
void main()
{
	uint32_t sys_id = get_syscall_id_by_name("NtOpenFile");

	printf("NtOpenFile -> 0x%X\n", sys_id);

	getchar();
} 
*/

void main()
{
	FILE* hFile = fopen("output.txt", "w");

	uint64_t base = (uint64_t)GetModuleHandleA("ntdll");
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(base + dos_header->e_lfanew);

	IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + nt_header->OptionalHeader.DataDirectory[0].VirtualAddress);

	uint32_t* name_rva = (uint32_t*)(base + exports->AddressOfNames);

	uint8_t pre_syscall_pattern[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
	uint8_t post_syscall_pattern[] = { 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03, 0x0F, 0x05, 0xC3, 0xCD, 0x2E, 0xC3, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (uint32_t i = 0; i < exports->NumberOfNames; ++i)
	{

		uint32_t* function = (uint32_t*)(base + exports->AddressOfFunctions);
		uint16_t* ordinal = (uint16_t*)(base + exports->AddressOfNameOrdinals);
		uint64_t address = (uint64_t)base + function[ordinal[i]];

		uint8_t pre_syscall[4] = { 0 };
		memcpy(pre_syscall, (void*)address, 4);

		uint8_t post_syscall[24] = { 0 };
		memcpy(post_syscall, (void*)(address + 8), 24);

		if ((memcmp(&pre_syscall, &pre_syscall_pattern, 4) != 0) || (memcmp(&post_syscall, &post_syscall_pattern, 4) != 0))
			continue;

		const char* name = (char*)(base + name_rva[i]);
		uint32_t sys_id = LittletoBigEndian((uint8_t*)(address + 4));

		fprintf(hFile, "0x%X %s\n", sys_id, name);
	}

	fclose(hFile);
}

