#pragma once

#include <Windows.h>
#include <cstdint>

struct DOSHeader
{
	char signature[2];
	short last_size;
	short nblocks;
	short n_reloc;
	short hdrsize;
	short minalloc;
	short maxlaloc;
	uint16_t ss;
	uint16_t sp;
	short checksum;
	uint16_t ip;
	uint16_t cs;
	short relocpos;
	short noverlay;
	short serverzed1[4];
	short oem_id;
	short oem_info;
	short reserved2[10];
	uint32_t e_lfanew;
};

struct COFFHeader
{
	short machine;
	short numberOfSections;
	int timeDateStamp;
	int ptrToSymbolTable;
	int numberOfSymbols;
	short sizeOfOptionalHeader;
	short characteristics;
};

struct DataDirectory // RVA and size of the data
{
	DWORD VirtualAddress;
	DWORD size;
};

struct PEOptHeader
{
	short signature;
	char majorLinkerVersion;
	char minorLinkerVersion;
	DWORD sizeOfCode;
	DWORD sizeOfInitializedData;
	DWORD sizeOfUninitializedData;
	DWORD addrOfEntryPoint;
	DWORD baseOfCode;
	DWORD baseOfData;
	DWORD imageBase;
	DWORD sectionAlignment;
	DWORD fileAlignment;
	short majorOSVersion;
	short minorOSVersion;
	short majorImageVersion;
	short minorImageVersion;
	short majorSubsystemVersion;
	short minorSubsystemVerson;
	DWORD reserved;
	DWORD sizeOfImage;
	DWORD sizeOfHeaders;
	DWORD checksum;
	short subsystem;
	short dllCharacteristics;
	DWORD sizeOfStackReserve;
	DWORD sizeOfStackCommit;
	DWORD sizeOfHeapReserve;
	DWORD sizeofHeapCommit;
	DWORD loaderFlags;
	DWORD numberOfRVAandSizes;
	DataDirectory data_directory[16];
};

struct SectionHeader
{
	char name[8];
	uint32_t virtualSize;
	uint32_t virtualAddress;
	uint32_t rawDataSize;
	uint32_t rawDataOffset;
	uint32_t relocationsOffset;
	uint32_t lineNumbersOffsets;
	uint16_t numberOfRelocations;
	uint16_t numberOfLineNumbers;
	uint32_t characteristics;
};

enum ImageSectionCharacteristics {
	IIMAGE_SCN_CNT_CODE = 0x00000020,
	IIMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
	IMAGE_SCN_MEM_READ_EXECUTE = 0x60000000
};
