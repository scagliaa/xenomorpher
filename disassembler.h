#pragma once

#ifndef DECOMPILER_H
#define DECOMPILER_H

#include <vector>
#include <map>
#include <set>
#include <cstdint>
#include <cstddef>

#include "PEParser.h"

enum class REGISTER
{
	EAX,
	ECX,
	EDX,
	EBX,
	ESP,
	EBP,
	ESI,
	EDI,
	NONE
};

enum DETECTED_TYPE
{
	CODE,
	DATA,
	POSSIBLE_DATA, // this could be data; shouldn't disassemble it
	UNKNOWN
};

enum class INSTRUCTION_TYPE
{
	OTHER, // instruction that doesn't have its own code
	NOP, // instructions that do nothing, not necesasrily 0x90
	C_JMP,
	UNC_JMP,
	CALL,
	RET,
	INT_CALL,
	x87_FPU,
	STACK // PUSH, POP
};

enum class OP_TYPE
{
	OTHER,
	NONE,
	GVEV,
	EVGV,
	GBEB,
	EBGB,
	GVM,
	IB,
	IV
};

enum class BRANCH_TYPE
{
	JMP,
	COND_JMP,
	CALL,
	REGULAR_JMP,
	REGULAR_COND_JMP,
	REGULAR_CALL
};

struct Branch
{
	BRANCH_TYPE type;
	uint32_t source;
	uint32_t dest;
};

struct BlockRegister
{
	int32_t value{ NULL };
	bool modified{ false };
	bool is_value_known = false;
	bool inherited_value = false;
};

struct Block
{
	uint32_t start_address;
	uint32_t end_address;
	std::vector<uint32_t>& dest_addresses;
	Block():start_address{},end_address{},dest_addresses( *(new std::vector<uint32_t>) ){}
};

uint8_t getMod(uint8_t modrm);
uint8_t getReg(uint8_t modrm);
uint8_t getRM(uint8_t modrm);

class Disassembler
{
public:
	Disassembler(PEParser& parser);
	void analyze(); // build the branches and blocks vectors
	const std::map<uint32_t, std::vector<uint8_t>>& getCode();
	void editInstruction(uint32_t addr, std::vector < uint8_t > instruction);
	static INSTRUCTION_TYPE getInstructionType(const std::vector<uint8_t>& instruction);
	static OP_TYPE getOperandsType(const std::vector<uint8_t>& instruction);
	static std::vector<uint8_t> remove_prefixes(const std::vector<uint8_t>& instruction);
	uint32_t getBranchDestination(uint32_t addr, std::vector<uint8_t>& instruction);
	void addOpCodes(std::vector<uint8_t>& instruction, uint32_t addr, unsigned count);
	static bool is_prefix(uint8_t op);
	bool isAddressInternal(uint32_t address);
	void UpdateVirtualImageFromInstructions();
protected:
	uint8_t readInstruction(uint32_t addr);
	void readCode(uint32_t addr);
	const char* generateOpCodeErrorInfo(const char* error, uint32_t addr);
	Block readBlocks(uint32_t addr);
	void analyzeBlock(Block& block);
	std::vector<Branch> getCrossReferences(uint32_t addr);
	bool hasCrossRefs(uint32_t addr);
	Block* getBlockOfAddr(uint32_t addr);
	bool isAddrInBlock(const uint32_t addr);
private:
	PEParser& parser;
	uint8_t*& VirtualImage;
	std::vector<std::pair<uint32_t, uint32_t>> code_bounds;
	uint32_t imageBase;
	uint32_t entryPoint;
	std::map<uint32_t, std::vector<uint8_t>> code;
	std::vector<Branch> branches;
	std::vector<Block> blocks;
	std::map<uint32_t, DETECTED_TYPE> referencedAddresses;
	std::multimap < uint32_t, uint32_t > references;
	uint32_t startOfEntrySection;
};

#endif