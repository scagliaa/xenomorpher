#pragma once

#ifndef PEPARSER_H
#define PEPARSER_H

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "PEFormat.h"
#include "relocation.h"

class PEParser
{
public:
	PEParser(uint8_t* data, size_t& data_size);
	PEParser() = default;
	~PEParser() = default;
	void operator = (const PEParser&) = delete;

	std::vector<std::string> GetSectionNames() const;
	std::pair<uint8_t*, size_t> GetSectionData(const std::string& section_name);
	size_t GetSectionRawSize(const std::string& section_name);
	uint32_t GetSectionRawAddress(const std::string& section_name);
	size_t GetSectionVirtualAddress(const std::string& section_name);
	uint32_t GetSectionVirtualSize(const std::string& section_name);
	uint32_t GetEntryPoint() const;
	uint32_t GetRelativeEntryPoint() const;
	uint8_t*& GetVirtualImage();
	std::pair<uint32_t, uint32_t> GetSectionVirtualBounds(const std::string& section_name);
	std::vector<std::pair<uint32_t, uint32_t>> GetCodeSectionsVirtualBounds();
	uint32_t GetImageBase() const;
	uint32_t GetCodeBase();
	std::pair<uint8_t*, size_t> GetData() const;
	void UpdateDataFromVirtualImage() const;
	uint32_t AddSection(const std::string& name, size_t size, uint32_t flags);
	void ExpandLastSectionBy(size_t size);
	void SetEntryPoint(uint32_t value) const;
	bool IsLastSectionRECode() const;
	uint32_t GetLastSectionEnd() const;
private:
	uint8_t* data;
	size_t& dataSize;
	uint8_t* virtualImage;
	size_t virtualImageSize;
	COFFHeader* coffHeader;
	PEOptHeader* peHeader;
	std::vector<SectionHeader*> sectionHeaders;
	std::vector<Relocation> relocations;
};

#endif

