#pragma once
#include <vector>
#include "types.h"
#include "ByteBuffer.h"
#include "crypto.h"

class Ivfc
{
public:
	static const int kBlockSize = 0x1000;

	Ivfc();
	~Ivfc();

	int CreateIvfcHashTree(const u8* level2, u64 level2_size);

	inline const u8* header_blob() const { return header_.data_const(); }
	inline u32 header_size() const { return header_.size(); }
	inline u32 used_header_size() const { return header_used_size_; }
	inline const u8* level0_blob() const { return level_[0].data_const(); }
	inline u64 level0_size() const { return level_[0].size(); }
	inline const u8* level1_blob() const { return level_[1].data_const(); }
	inline u64 level1_size() const { return level_[1].size(); }
private:
	static const int kLevelNum = 3;
	static const u32 kIvfcTypeRomfs = 0x10000;
	static const u32 kIvfcTypeExtdata = 0x20000;

#pragma pack (push, 1)
	struct sIvfcHeader
	{
		char magic[4];
		u32 type;
		u32 master_hash_size;
		struct sIvfcLevelHeader
		{
			u64 logical_offset;
			u64 size;
			u32 block_size;
			u8 reserved[4];
		} level[kLevelNum];
		u32 optional_size;
		u8 reserved[4];
	};
#pragma pack (pop)

	ByteBuffer header_;
	u32 header_used_size_;
	ByteBuffer level_[kLevelNum-1];
};

