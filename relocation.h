#pragma once
#include <cstdint>

enum RELOCATION_TYPE
{
	IIMAGE_REL_BASED_ABSOLUTE = 0,
	IIMAGE_REL_BASED_HIGH = 1,
	IIMAGE_REL_BASE_LOW = 2,
	IIMAGE_REL_BASED_HIGHLOW = 3,
	IIMAGE_REL_BASED_HIGHADJ = 4
};

struct RelocationChunk
{
	uint32_t virtual_address;
	uint32_t size_chunk;
};

struct Relocation
{
	uint16_t offset : 12;
	uint16_t type : 4;
};