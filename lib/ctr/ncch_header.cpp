#include <cstdio>
#include <cstring>
#include <cmath>
#include "ncch_header.h"


#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)


NcchHeader::NcchHeader() :
	access_descriptor_size_(0)
{
	memset((u8*)&header_, 0, sizeof(struct sNcchHeader));
	memcpy(header_.magic, kMagic, 4);
	SetBlockSize(kDefaultBlockSize);
}

NcchHeader::~NcchHeader()
{

}

int NcchHeader::CreateHeader(const Crypto::sRsa2048Key& ncch_rsa_key)
{
	u8 hash[Crypto::kSha256HashLen];

	// If the header size is 0, the ncch layout hasn't been determined
	if (header_.size == 0)
	{
		FinaliseNcchLayout();
	}

	// hash header
	Crypto::Sha256((u8*)header_.magic, sizeof(struct sNcchHeader) - 0x100, hash);
	// sign header
	safe_call(Crypto::RsaSign(ncch_rsa_key, Crypto::HASH_SHA256, hash, header_.signature));
	

	return 0;
}

int NcchHeader::SetHeader(const u8 * header)
{
	memcpy((u8*)&header_, header, sizeof(struct sNcchHeader));

	if (memcmp(header_.magic, kMagic, 4) != 0) die("[ERROR] Not a NCCH header!");

	return 0;
}

// Basic Data
void NcchHeader::SetTitleId(u64 title_id)
{
	header_.title_id = le_dword(title_id);
}

void NcchHeader::SetProgramId(u64 program_id)
{
	header_.program_id = le_dword(program_id);
}

void NcchHeader::SetMakerCode(const char* maker_code)
{
	memset(header_.maker_code, 0, kMakerCodeLen);
	strncpy(header_.maker_code, maker_code, kMakerCodeLen);
}

void NcchHeader::SetProductCode(const char* product_code)
{
	memset(header_.product_code, 0, kProductCodeLen);
	strncpy(header_.product_code, product_code, kProductCodeLen);
}

// Flags
void NcchHeader::SetNcchType(NcchHeader::ContentType content_type, NcchHeader::FormType form_type)
{
	header_.flags.content_type = ((form_type&3) | (content_type << 2));
	if ((form_type & 1) == 0)
	{
		header_.flags.other_flag |= NO_MOUNT_ROMFS;
	}

	header_.format_version = (form_type & 2);
}

void NcchHeader::SetPlatform(NcchHeader::Platform platform)
{
	header_.flags.platform = platform;
}

void NcchHeader::SetBlockSize(u32 size)
{
	header_.flags.block_size = log2l(size) - 9;
}

void NcchHeader::SetNoCrypto()
{
	header_.flags.other_flag &= ~(NO_AES|FIXED_AES_KEY|SEED_KEY);
	header_.flags.other_flag |= NO_AES;
}

void NcchHeader::SetFixedAesKey()
{
	header_.flags.other_flag &= ~(NO_AES|FIXED_AES_KEY|SEED_KEY);
	header_.flags.other_flag |= FIXED_AES_KEY;
}

void NcchHeader::SetSecureAesKey(u8 keyXindex)
{
	header_.flags.other_flag &= ~(NO_AES|FIXED_AES_KEY);
	header_.flags.key_x_index = keyXindex;
}

// Data segments
void NcchHeader::SetExheaderData(u32 size, u32 accessdesc_size, const u8 hash[Crypto::kSha256HashLen])
{
	header_.exheader_size = le_word(size);
	access_descriptor_size_ = accessdesc_size;
	memcpy(header_.exheader_hash, hash, Crypto::kSha256HashLen);
}

void NcchHeader::SetPlainRegionData(u32 size)
{
	header_.plain_region.size = le_word(size_to_block(size));
}

void NcchHeader::SetLogoData(u32 size, const u8 hash[Crypto::kSha256HashLen])
{
	header_.logo.size = le_word(size_to_block(size));
	memcpy(header_.logo_hash, hash, Crypto::kSha256HashLen);
}

void NcchHeader::SetExefsData(u32 size, u32 hashed_data_size, const u8 hash[Crypto::kSha256HashLen])
{
	header_.exefs.size = le_word(size_to_block(size));
	header_.exefs_hashed_data_size = le_word(size_to_block(hashed_data_size));
	memcpy(header_.exefs_hash, hash, Crypto::kSha256HashLen);
}

void NcchHeader::SetRomfsData(u32 size, u32 hashed_data_size, const u8 hash[Crypto::kSha256HashLen])
{
	header_.romfs.size = le_word(size_to_block(size));
	header_.romfs_hashed_data_size = le_word(size_to_block(hashed_data_size));
	memcpy(header_.romfs_hash, hash, Crypto::kSha256HashLen);
}

void NcchHeader::FinaliseNcchLayout()
{
	u32 size = size_to_block(sizeof(struct sNcchHeader));
	
	// exheader
	if (le_word(header_.exheader_size))
	{
		size += size_to_block(le_word(header_.exheader_size) + access_descriptor_size_);
	}

	// logo
	if (le_word(header_.logo.size))
	{
		header_.logo.offset = le_word(size);
		size += le_word(header_.logo.size);
	}

	// plain region
	if (le_word(header_.plain_region.size))
	{
		header_.plain_region.offset = le_word(size);
		size += le_word(header_.plain_region.size);
	}

	// exefs region
	if (le_word(header_.exefs.size))
	{
		header_.exefs.offset = le_word(size);
		size += le_word(header_.exefs.size);
	}

	// exefs region
	if (le_word(header_.romfs.size))
	{
		size = size_to_block(align(block_to_size(size), 0x1000));
		header_.romfs.offset = le_word(size);
		size += le_word(header_.romfs.size);
	}

	header_.size = le_word(size);
}
