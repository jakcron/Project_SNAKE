#include "program_id_v1.h"

ProgramId_v1::ProgramId_v1()
{
	program_id_ = 0;
}

ProgramId_v1::ProgramId_v1(uint64_t program_id)
{
	program_id_ = program_id;
}

void ProgramId_v1::operator=(uint64_t program_id)
{
	program_id_ = program_id;
}

uint64_t ProgramId_v1::program_id()
{
	return program_id_;
}

uint16_t ProgramId_v1::device_type()
{
	return get_device_type(program_id_);
}

uint16_t ProgramId_v1::category()
{
	return get_category(program_id_);
}

uint32_t ProgramId_v1::unique_id()
{
	return get_unique_id(program_id_);
}

uint8_t ProgramId_v1::variation()
{
	return get_variation(program_id_);
}

bool ProgramId_v1::IsCategoryBitsSet(uint16_t bitmask)
{
	return (get_category(program_id_) & bitmask) == bitmask;
}