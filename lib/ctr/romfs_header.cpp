#include "romfs_header.h"



RomfsHeader::RomfsHeader()
{
}

RomfsHeader::RomfsHeader(const u8 * data)
{
	DeserialiseData(data);
}


RomfsHeader::~RomfsHeader()
{
}

const u8 * RomfsHeader::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t RomfsHeader::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void RomfsHeader::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sRomfsHeader)) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	sRomfsHeader* hdr = (sRomfsHeader*)serialised_data_.data();

	// calculate offsets
	u32 pos = kSize;
	for (size_t i = 0; i < kRomfsSectionNum; i++)
	{
		sections_[i].set_offset(pos);
		pos += sections_[i].size();
	}
	data_offset_ = align(pos, Crypto::kAesBlockSize);

	// serialise data
	hdr->set_header_size(kSize);
	for (size_t i = 0; i < kRomfsSectionNum; i++)
	{
		hdr->set_section(i, sections_[i].offset(), sections_[i].size());
	}
	hdr->set_data_offset(data_offset_);
}

void RomfsHeader::SetDirInfo(u32 node_table_size, u32 hashmap_table_size)
{
	sections_[DIR_HASHMAP_TABLE].set_size(hashmap_table_size);
	sections_[DIR_NODE_TABLE].set_size(node_table_size);
}

void RomfsHeader::SetFileInfo(u32 node_table_size, u32 hashmap_table_size)
{
	sections_[FILE_HASHMAP_TABLE].set_size(hashmap_table_size);
	sections_[FILE_NODE_TABLE].set_size(node_table_size);
}

void RomfsHeader::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();

	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sRomfsHeader)) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	memcpy(serialised_data_.data(), data, sizeof(sRomfsHeader));
	const sRomfsHeader* hdr = (const sRomfsHeader*)serialised_data_.data_const();

	// corruption checks
	if (hdr->header_size() != sizeof(sRomfsHeader))
	{
		throw ProjectSnakeException(kModuleName, "Header is corrupt (invalid header size)");
	}

	if (hdr->section(DIR_HASHMAP_TABLE).size() % sizeof(u32) != 0 || hdr->section(FILE_HASHMAP_TABLE).size() % sizeof(u32) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Header is corrupt (invalid hash table length)");
	}

	// save section offsets and sizes
	for (size_t i = 0; i < kRomfsSectionNum; i++)
	{
		sections_[i].set_offset(hdr->section(i).offset());
		sections_[i].set_size(hdr->section(i).size());
	}
	data_offset_ = hdr->data_offset();
}

u32 RomfsHeader::GetDirHashMapTableOffset() const
{
	return sections_[DIR_HASHMAP_TABLE].offset();
}

u32 RomfsHeader::GetDirHashMapTableSize() const
{
	return sections_[DIR_HASHMAP_TABLE].size();
}

u32 RomfsHeader::GetDirNodeTableOffset() const
{
	return sections_[DIR_NODE_TABLE].offset();
}

u32 RomfsHeader::GetDirNodeTableSize() const
{
	return sections_[DIR_NODE_TABLE].size();
}

u32 RomfsHeader::GetFileHashMapTableOffset() const
{
	return sections_[FILE_HASHMAP_TABLE].offset();
}

u32 RomfsHeader::GetFileHashMapTableSize() const
{
	return sections_[FILE_HASHMAP_TABLE].size();
}

u32 RomfsHeader::GetFileNodeTableOffset() const
{
	return sections_[FILE_NODE_TABLE].offset();
}

u32 RomfsHeader::GetFileNodeTableSize() const
{
	return sections_[FILE_NODE_TABLE].size();
}

u32 RomfsHeader::GetDataOffset() const
{
	return data_offset_;
}

void RomfsHeader::ClearDeserialisedVariables()
{
	for (size_t i = 0; i < kRomfsSectionNum; i++)
	{
		sections_[i].clear();
	}
	data_offset_ = 0;
}
