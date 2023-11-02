#include "PEParser.h"

#include <locale>
#include <ranges>
#include <span>

PEParser::PEParser(uint8_t* data, size_t& data_size) :
    // Initialize member variables
    data(data), dataSize(data_size), virtualImage{},
	virtualImageSize{},
	coffHeader{}, peHeader{}
{
    // Check if the data size is smaller than the size of the DOSHeader
    if (dataSize < sizeof(DOSHeader))
        throw std::runtime_error("Too small.");

    // Check if the DOS signature is correct
    if (data[0] != 'M' || data[1] != 'Z')
        throw std::runtime_error("Wrong DOS signature.");

    // COFF HEADER
    // Get the offset of the PE magic number
    const size_t pe_magic_offset = reinterpret_cast<DOSHeader*>(data)->e_lfanew;
    // Check if the data size is smaller than the size of the COFFHeader
    if (dataSize < pe_magic_offset + 4 + sizeof(COFFHeader))
        throw std::runtime_error("Too small.");

    // Get the PE magic number
    uint8_t* PEMAGIC = data + pe_magic_offset;
    // Check if the PE signature is correct
    if (PEMAGIC[0] != 'P' || PEMAGIC[1] != 'E' || PEMAGIC[2] != '\0' || PEMAGIC[3] != '\0')
        throw std::runtime_error("Wrong PE signature.");

    // Get the COFF header
    coffHeader = reinterpret_cast<COFFHeader*>(PEMAGIC + 4);

    // Check if the machine type is i386
    if (coffHeader->machine != 0x14C) // i386
        throw std::runtime_error("Not i386");

    // Check if the size of the optional header is smaller than the size of the PEOptHeader
    if (static_cast<unsigned short>(coffHeader->sizeOfOptionalHeader) < sizeof(PEOptHeader))
        throw std::runtime_error("Optional PE header too small");

    // Check if the data size is smaller than the size of the COFFHeader and the optional header
    if (dataSize < pe_magic_offset + 4 + sizeof(COFFHeader) + coffHeader->sizeOfOptionalHeader)
        throw std::runtime_error("Too small");

    // Check if the file is an executable or a DLL
    if (coffHeader->characteristics & 0x2 && !coffHeader->characteristics & 0x2000)
        throw std::runtime_error("Not an executable or a DLL.");

    // Get the PE optional header
    peHeader = reinterpret_cast<PEOptHeader*>(reinterpret_cast<char*>(coffHeader) + sizeof(COFFHeader));

    // Check if the optional PE header signature is correct
    if (peHeader->signature != 0x10B)
        throw std::runtime_error("Wrong optional PE header sig");

    // Check if the subsystem is a console or a GUI
    if (peHeader->subsystem != 2 && peHeader->subsystem != 3)
        throw std::runtime_error("Subsystem is not a console nor a GUI");

    // TODO: Load section headers

    // TODO: Compute size of virtual image

    // TODO: Load virtual image

    // TODO: Rebase our various pointers on the virtual image
}

std::vector< std::string > PEParser::GetSectionNames() const 
{
    // Create a vector to store the names of the sections
    std::vector<std::string> names;
    
    // Reserve space in the vector for the number of section headers
    names.reserve(sectionHeaders.size());
    
    // Loop over each section header
    for( const auto section : sectionHeaders)
    {
        // Create a string with the name of the section (limited to 8 characters)
        std::string name(section->name, 8);
        
        // Erase any whitespace characters in the name
        name.erase(std::ranges::find_if( name, [](const char& a) -> bool
        {
            // Check if the character is a whitespace
            if (std::isspace<char>(a, std::locale())) 
                return true;
        }), end(name));
        
        // Assign the cleaned name back to the 'name' variable
        name = std::string( name );
        
        // Add the name to the vector of names
        names.push_back(name);
    }
    
    // Return the vector of names
    return names;
}

uint32_t PEParser::GetEntryPoint() const {
    // Get the address of the entry point from the PE header
    const unsigned long entry = peHeader->addrOfEntryPoint;

    // Iterate over all section headers
    for( const SectionHeader * header : sectionHeaders) {
        // Get the virtual address of the current section header
        const unsigned long start = header->virtualAddress;

        // Check if the entry point lies within the current section
        if ( const unsigned long limit = start + header->virtualSize; entry >= start && entry < limit)
            // If it does, return the entry point
            return entry;
    }

    // If the entry point is not found within any section, throw an error
    throw std::runtime_error("Can't find the section containing the entry point. Maybe packed?");
}
uint32_t PEParser::GetRelativeEntryPoint() const {
    // The entry point of the PE file
    const DWORD entry = peHeader->addrOfEntryPoint;

    // Loop through each section header
    for (const SectionHeader* h : sectionHeaders) {
        // The start of the section in virtual memory
        const DWORD start = h->virtualAddress;

        // The end of the section in virtual memory
        const DWORD limit = start + h->virtualSize;

        // If the entry point is within this section
        if (entry >= start && entry < limit) {
            // Return the physical address of the entry point
            // This is done by subtracting the virtual address of the section from the entry point
            return entry - h->virtualAddress;
        }
    }
    // If no section containing the entry point was found, throw an error
    throw std::runtime_error("Can't find the section containing the entry point.");
}

uint32_t PEParser::GetSectionRawAddress( const std::string& section_name ) {
    // Use the find_if algorithm from the ranges library to find the section header with the given name
    // The lambda function compares the name of each section header with the provided section name
    const auto it = std::ranges::find_if( sectionHeaders, [section_name]( const SectionHeader* header) {
        return std::string( std::string( header->name, 8 ) ) == section_name;
    });

    // If the section header is not found, throw an invalid_argument exception
    if (it == end(sectionHeaders))
        throw std::invalid_argument("Section doesn't exist");

    // If the section header is found, return the raw data offset of the section
    return (*it)->rawDataOffset;
}

uint32_t PEParser::GetSectionVirtualSize( const std::string& section_name )
{
    // Use the find_if algorithm from the ranges library to find the section with the given name
    // The lambda function checks if the name of the current section header matches the given section name
    const auto it = std::ranges::find_if(sectionHeaders, [section_name](const SectionHeader* header) {
        return std::string(std::string(header->name, 8)) == section_name;
        });

    // If the section with the given name is not found, throw an invalid_argument exception
    if (it == end(sectionHeaders))
        throw std::invalid_argument("Section doesn't exist");

    // If the section is found, return its virtual size
    return (*it)->virtualSize;
}

uint8_t*& PEParser::GetVirtualImage() {
    return virtualImage;
}

std::pair<uint32_t, uint32_t> PEParser::GetSectionVirtualBounds(const std::string& section_name) {
    // Use the C++20 ranges library to find the section with the given name
    const auto it = std::ranges::find_if(sectionHeaders, [&section_name](const SectionHeader* header) {
        // Compare the name of the section with the given name
        return std::string(header->name, 8) == section_name;
        });

    // If the section was not found, throw an exception
    if (it == std::end(sectionHeaders))
        throw std::invalid_argument("Section doesn't exist");

    // Get the start and end of the section in virtual memory
    auto start = (*it)->virtualAddress;
    auto end = start + (*it)->virtualSize;

    // Return the start and end as a pair
    return { start, end };
}

uint32_t PEParser::GetImageBase() const {
    return peHeader->imageBase;
}

uint32_t PEParser::GetCodeBase() {
    return peHeader->baseOfCode;
}

std::vector< std::pair< uint32_t, uint32_t > > PEParser::GetCodeSectionsVirtualBounds() {
    // Vector to store the virtual bounds of the code sections
    std::vector<std::pair<uint32_t, uint32_t>> bounds;

    // Loop through each section header
    for (const SectionHeader* h : sectionHeaders) {
        // Check if the section is executable
        if (h->characteristics & IMAGE_SCN_MEM_EXECUTE) {
            // Get the start and end of the section in virtual memory
            auto start = h->virtualAddress;
            auto end = start + h->virtualSize;

            // Add the virtual bounds to the vector
            bounds.emplace_back( start, end );
        }
    }

    // If no code section was found, throw an exception
    if (bounds.empty())
        throw std::runtime_error("No code section found.");

    // Return the vector of virtual bounds
    return bounds;
}

void PEParser::UpdateDataFromVirtualImage() const {
    // Loop through each section header
    for ( const SectionHeader* h : sectionHeaders) {
        // Check if the section is writable
        if (h->characteristics & IMAGE_SCN_MEM_WRITE) {
            // Get the start and end of the section in virtual memory
            const auto start = h->virtualAddress;
            const auto end = start + h->virtualSize;

            // Get the raw data pointer and size
            const auto raw_data_ptr = h->rawDataOffset;
            const auto raw_data_size = h->rawDataSize;

            // Copy the headers back
            std::copy(reinterpret_cast<uint8_t*>(start),
                reinterpret_cast<uint8_t*>(end),
                reinterpret_cast<uint8_t*>(raw_data_ptr));

            // Copy the sections back
            std::copy(reinterpret_cast<uint8_t*>(raw_data_ptr),
                reinterpret_cast<uint8_t*>(raw_data_ptr + raw_data_size),
                reinterpret_cast<uint8_t*>(start));
        }
    }
}

void PEParser::SetEntryPoint( uint32_t value ) const {
    peHeader->addrOfEntryPoint = value;
}

std::pair< uint8_t*, size_t > PEParser::GetData() const
{
    return { data, dataSize };
}


uint32_t PEParser::AddSection( const std::string& name, size_t size, uint32_t flags )
{
    // Align the start of the raw data to the file alignment boundary
    uint32_t aligned_raw_start = dataSize;
    if (aligned_raw_start % peHeader->fileAlignment)
        aligned_raw_start += peHeader->fileAlignment - dataSize % peHeader->fileAlignment;

    // Align the start of the virtual data to the section alignment boundary
    uint32_t aligned_virtual_start = virtualImageSize;
    if (aligned_virtual_start % peHeader->sectionAlignment)
        aligned_virtual_start += peHeader->sectionAlignment - virtualImageSize % peHeader->sectionAlignment;

    // Calculate the end of the raw and virtual data after adding the new section
    uint32_t aligned_raw_end = aligned_raw_start + size;
    uint32_t aligned_virtual_end = aligned_virtual_start + size;

    // Check if there is enough room for the new section header
    size_t new_headers = reinterpret_cast< uint8_t* >( sectionHeaders.back() + 2 ) - virtualImage;
    if (new_headers >= sectionHeaders[0]->rawDataOffset)
        throw std::runtime_error("There is not enough room for the new section header.");

    // Save the old image address before reallocating memory
    uint8_t* old_image_address = virtualImage;

    // Reallocate memory for the raw and virtual data
    data = static_cast<uint8_t*>(realloc(data, aligned_raw_end));
    virtualImage = static_cast<uint8_t*>(realloc(virtualImage, aligned_virtual_end));

    // Update the section headers, COFF header, and PE optional header to the new memory location
    for ( auto & section_header : sectionHeaders )
	    section_header = reinterpret_cast< SectionHeader* >( reinterpret_cast< uint32_t >( section_header ) 
																- reinterpret_cast< uint32_t >( old_image_address )
																	+ reinterpret_cast< uint32_t >( virtualImage ) );
    coffHeader = reinterpret_cast< COFFHeader* >( reinterpret_cast< uint32_t >( coffHeader ) - reinterpret_cast< uint32_t >( old_image_address ) + reinterpret_cast< uint32_t >( virtualImage ) );
    peHeader = reinterpret_cast< PEOptHeader* >( ( uint32_t )peHeader - ( uint32_t )old_image_address + ( uint32_t )virtualImage );

    // Create the section header for the new section
    SectionHeader* new_header = sectionHeaders.back() + 1;
    new_header->characteristics = flags;
    new_header->lineNumbersOffsets = NULL;
    strncpy(new_header->name, name.c_str(), 8);
    new_header->numberOfLineNumbers = 0;
    new_header->numberOfRelocations = 0;
    new_header->rawDataOffset = aligned_raw_start;
    new_header->rawDataSize = size;
    new_header->relocationsOffset = 0;
    new_header->virtualAddress = aligned_virtual_start;
    new_header->virtualSize = size;

    // Update the metadata in the COFF header and PE optional header
    coffHeader->numberOfSections++;
    peHeader->sizeOfImage += aligned_virtual_end - aligned_virtual_start;
    if(flags & IIMAGE_SCN_CNT_CODE)
    {
        peHeader->sizeOfCode += aligned_virtual_end - aligned_virtual_start;
        peHeader->sizeOfInitializedData += aligned_virtual_end - aligned_virtual_start;
    }

    // Update the size of the raw and virtual data
    dataSize = aligned_raw_end;
    virtualImageSize = aligned_virtual_end;

    // Return the virtual address of the new section
    return (uint32_t)new_header->virtualAddress;
}

// Expand the last section of the PE file by the given size
// Use std::vector and std::span from C++20 instead of raw pointers
void PEParser::ExpandLastSectionBy(size_t size) {

    // Get span to original image
    std::span<uint8_t> originalImage{ virtualImage, virtualImageSize };


    data = (uint8_t*)std::realloc(data, dataSize + size);

    // Reallocate virtual image buffer
    virtualImage = (uint8_t*)std::realloc(virtualImage, virtualImageSize + size);

    // Update section headers to point to new virtual image location
    for (auto& sectionHeader : sectionHeaders) {
        sectionHeader = reinterpret_cast<SectionHeader*>(
            reinterpret_cast<uintptr_t>(sectionHeader) -
            reinterpret_cast<uintptr_t>(originalImage.data()) +
            reinterpret_cast<uintptr_t>(virtualImage));
    }

    // Update COFF and PE headers
    coffHeader = reinterpret_cast<COFFHeader*>(
        reinterpret_cast<uintptr_t>(coffHeader) -
        reinterpret_cast<uintptr_t>(originalImage.data()) +
        reinterpret_cast<uintptr_t>(virtualImage));

    peHeader = reinterpret_cast<PEOptHeader*>(
        reinterpret_cast<uintptr_t>(peHeader) -
        reinterpret_cast<uintptr_t>(originalImage.data()) +
        reinterpret_cast<uintptr_t>(virtualImage));

    // Get last section header
    const auto& header = sectionHeaders.back();

    // Update sizes
    header->rawDataSize += size;
    header->virtualSize += size;
    peHeader->sizeOfImage += size;

    if (header->characteristics & IMAGE_SCN_CNT_CODE) {
        peHeader->sizeOfCode += size;
        peHeader->sizeOfInitializedData += size;
    }

    // Update data sizes
    dataSize += size;
    virtualImageSize += size;
}

bool PEParser::IsLastSectionRECode() const {
    const SectionHeader* header = sectionHeaders.back();
    if ( constexpr uint32_t flags = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ_EXECUTE; (header->characteristics & flags) == flags)
        return true;
    return false;
}

uint32_t PEParser::GetLastSectionEnd() const {
	const SectionHeader* header = sectionHeaders.back();
    return header->virtualAddress + header->virtualSize;
}

