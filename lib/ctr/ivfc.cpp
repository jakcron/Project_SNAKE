#include <cmath>
#include "ivfc.h"

#define IVFC_MAGIC "IVFC"

#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

Ivfc::Ivfc()
{
}

Ivfc::~Ivfc()
{
}

int Ivfc::CreateIvfcHashTree(const u8* level2, u64 level2_size)
{
	struct sIvfcHeader hdr;
	memset((u8*)&hdr, 0, sizeof(struct sIvfcHeader));

	memcpy(hdr.magic, IVFC_MAGIC, 4);
	hdr.type = le_word(kIvfcTypeRomfs);

	// set data level size
	hdr.level[2].size = le_dword(level2_size);
	hdr.level[2].block_size = le_word(log2l(kBlockSize));
	hdr.level[1].size = le_dword((align(le_dword(hdr.level[2].size), kBlockSize) / kBlockSize) * Crypto::kSha256HashLen);
	hdr.level[1].block_size = le_word(log2l(kBlockSize));
	hdr.level[0].size = le_dword((align(le_dword(hdr.level[1].size), kBlockSize) / kBlockSize) * Crypto::kSha256HashLen);
	hdr.level[0].block_size = le_word(log2l(kBlockSize));

	// set "logical" offsets
	hdr.level[0].logical_offset = 0;
	for (int i = 1; i < kLevelNum; i++)
	{
		hdr.level[i].logical_offset = le_dword(align(le_dword(hdr.level[i - 1].logical_offset) + le_dword(hdr.level[i - 1].size), kBlockSize));
	}

	// set master hash size & optional size
	hdr.master_hash_size = le_word((align(le_dword(hdr.level[0].size), kBlockSize) / kBlockSize) * Crypto::kSha256HashLen);
	hdr.optional_size = le_word(sizeof(struct sIvfcHeader));
	
	// save used header size
	header_used_size_ = align(sizeof(struct sIvfcHeader), 0x10) + le_word(hdr.master_hash_size);

	// allocate memory for each hash level & the header
	safe_call(level_[1].alloc(align(le_dword(hdr.level[1].size), kBlockSize)));
	safe_call(level_[0].alloc(align(le_dword(hdr.level[0].size), kBlockSize)));
	safe_call(header_.alloc(align(align(sizeof(struct sIvfcHeader),0x10) + le_dword(hdr.master_hash_size), kBlockSize)));

	// create level 1 hashes from level 2
	for (size_t i = 0; i < (level2_size / kBlockSize); i++)
	{
		Crypto::Sha256(level2 + kBlockSize*i, kBlockSize, level_[1].data() + Crypto::kSha256HashLen*i);
	}
	// if there was additional data after the last whole block
	// copy the remaining data into a block, and hash that
	if ((level2_size % kBlockSize) > 0)
	{
		u8 block[kBlockSize] = { 0 };
		memcpy(block, level2 + ((level2_size / kBlockSize)*kBlockSize), (level2_size % kBlockSize));
		Crypto::Sha256(block, kBlockSize, level_[1].data() + Crypto::kSha256HashLen*(level2_size / kBlockSize));
	}

	// create level 0 hashes from level 1
	for (size_t i = 0; i < (level_[1].size() / kBlockSize); i++)
	{
		Crypto::Sha256(level_[1].data() + kBlockSize*i, kBlockSize, level_[0].data() + Crypto::kSha256HashLen*i);
	}

	// create master hashes from level 0
	for (size_t i = 0; i < (level_[0].size() / kBlockSize); i++)
	{
		Crypto::Sha256(level_[0].data() + kBlockSize*i, kBlockSize, header_.data() + align(sizeof(struct sIvfcHeader), 0x10) + Crypto::kSha256HashLen*i);
	}

	// copy header into header buffer
	memcpy(header_.data(), (u8*)&hdr, sizeof(struct sIvfcHeader));

	return 0;
}