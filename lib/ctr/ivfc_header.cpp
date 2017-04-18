#include "ivfc_header.h"



IvfcHeader::IvfcHeader()
{
	ClearDeserialisedVariables();
}

IvfcHeader::IvfcHeader(const u8 * data)
{
	DeserialiseData(data);
}


IvfcHeader::IvfcHeader(const IvfcHeader & other)
{
	DeserialiseData(other.GetSerialisedData());
}

IvfcHeader::~IvfcHeader()
{
}

void IvfcHeader::operator=(const IvfcHeader & other)
{
	DeserialiseData(other.GetSerialisedData());
}

void IvfcHeader::ValidateIvfcType(IvfcType type)
{
	if (type != IVFC_ROMFS && type != IVFC_EXTDATA)
	{
		throw ProjectSnakeException(kModuleName, "IVFC header is corrupt (invalid type)");
	}
}

u64 IvfcHeader::GetDefaultBlockSize(IvfcType type)
{
	u64 size = 0;
	switch (type)
	{
	case(IVFC_ROMFS):
		size = kDefaultRomfsBlockSize;
		break;
	case(IVFC_EXTDATA):
		size = kDefaultExtdataBlockSize;
		break;
	default:
		ValidateIvfcType(type);
	}

	return size;
}

u64 IvfcHeader::CalculateHashNum(u64 size, u64 block_size)
{
	return align(size, block_size) / block_size;
}

void IvfcHeader::ClearDeserialisedVariables()
{
	type_ = IvfcType::IVFC_ROMFS;
	master_hash_size_ = 0;
	optional_size_ = 0;
	for (size_t i = 0; i < kLevelNum; i++)
	{
		level_[i].clear();
	}
}

const u8 * IvfcHeader::GetSerialisedData() const
{
	return serialised_data_.data();
}

size_t IvfcHeader::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void IvfcHeader::SerialiseData(u64 level_2_size, IvfcType type)
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sIvfcHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	sIvfcHeader* hdr = (sIvfcHeader*)serialised_data_.data();

	// Validate type
	type_ = type;
	ValidateIvfcType(type_);

	// Commit static data
	hdr->set_struct_signature(kIvfcStructSignature);
	hdr->set_type(type_);
	hdr->set_optional_size(sizeof(sIvfcHeader));

	// Generate logical IVFC layout
	u64 block_size = GetDefaultBlockSize(type_);

	// 1. establish level 2 data
	level_[2].set_size(level_2_size);
	level_[2].set_block_size(block_size);

	// 2. calulate hash levels
	for (size_t i = 1; i <= 0; i--)
	{
		level_[i].set_size(CalculateHashNum(level_[i+1].size(), level_[i+1].block_size()) * Crypto::kSha256HashLen);
		level_[i].set_block_size(block_size);
	}

	// 3. determine master hash size
	master_hash_size_ = CalculateHashNum(level_[0].size(), level_[0].block_size()) * Crypto::kSha256HashLen;

	// 4. calculate level offsets
	level_[0].set_offset(0);
	for (size_t i = 1; i < kLevelNum; i++)
	{
		level_[i].set_offset(align(level_[i-1].size(), level_[i-1].block_size()));
	}

	// Commit Level data
	for (size_t i = 0; i < kLevelNum; i++)
	{
		hdr->set_level(i, level_[i].offset(), level_[i].size(), level_[i].block_size());
	}
}

void IvfcHeader::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();

	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sIvfcHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	memcpy(serialised_data_.data(), data, sizeof(sIvfcHeader));

	
	const sIvfcHeader* hdr = (const sIvfcHeader*)serialised_data_.data();

	// check for corruption
	if (memcmp(hdr->struct_signature(), kIvfcStructSignature, 4) != 0)
	{
		throw ProjectSnakeException(kModuleName, "IVFC header is corrupt (incorrect header bytes)");
	}

	ValidateIvfcType(hdr->type());

	type_ = hdr->type();
	master_hash_size_ = hdr->master_hash_size();
	optional_size_ = hdr->optional_size();
	for (size_t i = 0; i < kLevelNum; i++)
	{
		level_[i].set_offset(hdr->level(i).offset());
		level_[i].set_size(hdr->level(i).size());
		level_[i].set_block_size(hdr->level(i).block_size());
	}
}

IvfcHeader::IvfcType IvfcHeader::GetType() const
{
	return type_;
}

u32 IvfcHeader::GetMasterHashSize() const
{
	return master_hash_size_;
}

u64 IvfcHeader::GetLevelOffset(size_t index) const
{
	if (index >= kLevelNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal IVFC level");
	}

	return level_[index].offset();
}

u64 IvfcHeader::GetLevelSize(size_t index) const
{
	if (index >= kLevelNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal IVFC level");
	}

	return level_[index].size();
}

u64 IvfcHeader::GetLevelBlockSize(size_t index) const
{
	if (index >= kLevelNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal IVFC level");
	}

	return level_[index].block_size();
}

u64 IvfcHeader::GetLevelAlignedSize(size_t index) const
{
	return align(GetLevelSize(index), GetLevelBlockSize(index));
}

u32 IvfcHeader::GetOptionalSize() const
{
	return optional_size_;
}
