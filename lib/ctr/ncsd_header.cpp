#include <cstdio>
#include <cstring>
#include <cmath>
#include "ncsd_header.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

NcsdHeader::NcsdHeader()
{
	memset((u8*)&header_, 0, sizeof(sNcsdHeader));
	memcpy(header_.magic, kMagic, 4);
	SetBlockSize(kDefaultBlockSize);
}

NcsdHeader::~NcsdHeader()
{
}

int NcsdHeader::CreateHeader(const Crypto::sRsa2048Key & ncsd_rsa_key)
{
	u8 hash[Crypto::kSha256HashLen];

	// If the header size is 0, the ncch layout hasn't been determined
	if (header_.size == 0)
	{
		FinaliseNcsdLayout();
	}

	// hash header
	Crypto::Sha256((u8*)header_.magic, sizeof(struct sNcsdHeader) - 0x100, hash);
	// sign header
	safe_call(Crypto::SignRsa2048(ncsd_rsa_key, Crypto::HASH_SHA256, hash, header_.signature));


	return 0;
}

int NcsdHeader::SetHeader(const u8 * header)
{
	memcpy((u8*)&header_, header, sizeof(sNcsdHeader));

	if (memcmp(header_.magic, kMagic, 4) != 0) die("[ERROR] Not a NCSD header!");

	return 0;
}

int NcsdHeader::ValidateHeaderSignature(const Crypto::sRsa2048Key & ncsd_rsa_key)
{
	// hash header
	u8 hash[Crypto::kSha256HashLen];
	Crypto::Sha256((u8*)header_.magic, sizeof(struct sNcsdHeader) - 0x100, hash);
	// sign header
	safe_call(Crypto::VerifyRsa2048(ncsd_rsa_key, Crypto::HASH_SHA256, hash, header_.signature));
}

void NcsdHeader::SetTitleId(u64 title_id)
{
	header_.title_id = le_dword(title_id);
}

void NcsdHeader::SetCardDevice(CardDevice device)
{
	header_.flags.card_device_old = 0;
	header_.flags.card_device = (u8)device;
}

void NcsdHeader::SetPlatform(Platform platform)
{
	header_.flags.platform = (u8)platform;
}

void NcsdHeader::SetMediaType(MediaType type)
{
	header_.flags.media_type = (u8)type;
}

void NcsdHeader::SetBlockSize(u32 size)
{
	if (size < 0x200)
	{
		header_.flags.block_size = 0;
		return;
	}

	header_.flags.block_size = log2l(size) - 9;
}

void NcsdHeader::SetSection(u8 index, SectionFsType fs_type, SectionCryptoType crypto_type, u64 size)
{
	if (index > kSectionNum) return;

	header_.section_fs_type[index] = (u8)fs_type;
	header_.section_crypto_type[index] = (u8)crypto_type;
	header_.section_location[index].size = size_to_block(align(size, block_size()));
}

void NcsdHeader::SetSection(u8 index, u64 size)
{
	SetSection(index, FS_TYPE_NONE, CRYPTO_TYPE_NONE, size);
}

void NcsdHeader::SetCardInfoHeader(u32 size)
{
	card_info_header_size_ = size;
}

void NcsdHeader::FinaliseNcsdLayout()
{
	u32 size = size_to_block(sizeof(sNcsdHeader));

	size += size_to_block(0x4000 - sizeof(sNcsdHeader));

	for (int i = 0; i < kSectionNum; i++) 
	{
		// skip empty sections
		if (le_word(header_.section_location[i].size) == 0) continue;

		header_.section_location[i].offset = le_word(size);
		size += le_word(header_.section_location[i].size);
	}

	header_.size = le_word(size);
}
