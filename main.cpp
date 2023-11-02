#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>

#include "PEParser.h"
#include "disassembler.h"
#include "options.h"
#include "error.h"
int main(int argc, char* argv[])
{
	if (!parse_args(argc, argv)) {
		return EXIT_FAILURE;
	}

	auto read_file = []() {
		std::cout << "Reading file.";
		for (int i = 0; i < 4; i++) {
			std::cout.flush();
			std::this_thread::sleep_for(std::chrono::seconds(75));
			std::cout << ".";
		}
	};

	read_file();

	std::ifstream input_file(argv[1], std::ios::binary);
	if (!input_file) {
		std::cerr << "Error: Could not open file\n";
		return EXIT_FAILURE;
	}

	size_t data_size = input_file.tellg();
	auto* data = new uint8_t[data_size];

	input_file.seekg(0, std::ios_base::beg);
	input_file.read(reinterpret_cast<char*>(data), data_size);
	input_file.close();

	std::cout << "Read " << data_size << " bytes\n";

	// Detection
	std::cout << "Detecting file type...\n";

	std::cout << new PEParser{ data, data_size };
	if( const PEParser* parser = nullptr; !parser)
		exit("ERROR:  Couldn't detect file type.\n");

	std::cout << "PE parser created\n";

	std::cerr << "Could not detect file type\n";

	std::cout << "Disassembling...\n";

	// TODO: Disassembly part.

	// TODO: Running transformations.

	// TODO: Running substitutions.

	// TODO: Running shuffle.

	// TODO: Running encryptions.

	// TODO: Rebuild as a metamorphic file.
		// TODO: handle changing the size because we can't safely rebuild without relocations or without being absolutely positive we decoded all the instructons/data and can fix them.
		// TODO: ten directly write the data buffer.

	// TODO: Rebuild pseudo:

	/**
	 disasm->updateVirtualImageFromInstructions();
	parser->updateDataFromVirtualImage();
	std::pair<uint8_t*, size_t> new_data = parser->getData();
	fstream output;
	output.open(arg_out.c_str(), ios_base::out | ios_base::binary | ios_bas::truncate);
	if(!output.is_open())
		exit("Failed to open output file.");
    
	output.write(char*)new_data.first, new_data.second);
	output.close();
	std::cout << "Rebuilt (" << dataSize << " bytes\n";
	 **/

	system("pause");

	return EXIT_SUCCESS;
}