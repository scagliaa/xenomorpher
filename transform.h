#pragma once
#include "disassembler.h"

class Transform
{
public:
	Transform(Disassembler& disassembler, PEParser& parser, uint8_t rand);
	unsigned substitute();
	unsigned shuffle();
	unsigned short encrypt_section(std::string section_name);
protected:
	bool get_rand_bool();
private:
	Disassembler& disasm;
	PEParser& parser;
	uint8_t rand;
};
