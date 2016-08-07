#pragma once
#include "types.h"
#include "crypto.h"

class NcchHeader
{
public:
	enum FormType
	{
		UNASSIGNED,
		SIMPLE_CONTENT,
		EXECUTABLE_WITHOUT_ROMFS,
		EXECUTABLE
	};

	enum ContentType
	{
		APPLICATION,
		SYSTEM_UPDATE,
		MANUAL,
		CHILD,
		TRIAL,
		EXTENDED_SYSTEM_UPDATE
	};

	enum Platform
	{
		CTR = 1,
		SNAKE = 2
	};

	NcchHeader();
	~NcchHeader();

	// create + sign header
	int CreateHeader(const Crypto::sRsa2048Key& ncch_rsa_key);
	inline const u8* header_blob() const { return (u8*)&header_; }
	inline u32 header_size() const { return sizeof(struct sNcchHeader); }

	// Set header for parsing ncch headers
	int SetHeader(const u8* header);

	// Basic Data
	void SetTitleId(u64 title_id);
	void SetProgramId(u64 program_id);
	void SetMakerCode(const char* maker_code);
	void SetProductCode(const char* product_code);
	
	// Flags
	void SetNcchType(ContentType contentType, FormType formType);
	void SetPlatform(Platform platorm);
	void SetBlockSize(u32 size);
	void SetNoCrypto();
	void SetFixedAesKey();
	void SetSecureAesKey(u8 keyXindex);

	// Data segments
	void SetExheaderData(u32 size, u32 accessdesc_size, const u8 hash[Crypto::kSha256HashLen]);
	void SetPlainRegionData(u32 size);
	void SetLogoData(u32 size, const u8 hash[Crypto::kSha256HashLen]);
	void SetExefsData(u32 size, u32 hashedDataSize, const u8 hash[Crypto::kSha256HashLen]);
	void SetRomfsData(u32 size, u32 hashedDataSize, const u8 hash[Crypto::kSha256HashLen]);
	void FinaliseNcchLayout();

	// Get data from header
	inline u64 title_id() const { return le_dword(header_.title_id); }
	inline u64 program_id() const { return le_dword(header_.program_id); }
	inline bool is_encrypted() const { return (header_.flags.other_flag & NO_AES) == 0; }
	inline bool is_fixed_aes_key() const { return (header_.flags.other_flag & FIXED_AES_KEY) != 0; }
	inline bool is_seeded_aes_key() const { return (header_.flags.other_flag & SEED_KEY) != 0; }
	inline bool is_cfa() const { return (header_.flags.content_type & 3) == SIMPLE_CONTENT; }
	inline u64 ncch_size() const { return block_to_size(le_word(header_.size)); }
	inline u32 exheader_offset() const { return exheader_size() ? sizeof(struct sNcchHeader) : 0; }
	inline u32 exheader_size() const { return le_word(header_.exheader_size); }
	inline u32 accessdesc_offset() const { return exheader_offset() + exheader_size(); }
	inline u32 accessdesc_size() const { return exheader_size(); }
	inline u64 plain_region_offset() const { return block_to_size(le_word(header_.plain_region.offset)); }
	inline u64 plain_region_size() const { return block_to_size(le_word(header_.plain_region.size)); }
	inline u64 logo_offset() const { return block_to_size(le_word(header_.logo.offset)); }
	inline u64 logo_size() const { return block_to_size(le_word(header_.logo.size)); }
	inline u64 exefs_offset() const { return block_to_size(le_word(header_.exefs.offset)); }
	inline u64 exefs_size() const { return block_to_size(le_word(header_.exefs.size)); }
	inline u64 romfs_offset() const { return block_to_size(le_word(header_.romfs.offset)); }
	inline u64 romfs_size() const { return block_to_size(le_word(header_.romfs.size)); }


private:
	const char kMagic[4] = { 'N', 'C', 'C', 'H' };
	static const u32 kDefaultBlockSize = 0x200;
	static const int kMakerCodeLen = 0x2;
	static const int kProductCodeLen = 0x10;


	enum OtherFlag
	{
		FIXED_AES_KEY = BIT(0),
		NO_MOUNT_ROMFS = BIT(1),
		NO_AES = BIT(2),
		SEED_KEY = BIT(5),
		MANUAL_DISCLOSURE = BIT(6),
	};

	struct sSectionGeometry
	{
		u32 offset;
		u32 size;
	};

	struct sNcchHeader
	{
		u8 signature[Crypto::kRsa2048Size];
		char magic[4];
		u32 size;
		u64 title_id;
		char maker_code[kMakerCodeLen];
		u16 format_version;
		u32 seed_check;
		u64 program_id;
		u8 reserved1[0x10];
		u8 logo_hash[Crypto::kSha256HashLen];
		char product_code[kProductCodeLen];
		u8 exheader_hash[Crypto::kSha256HashLen];
		u32 exheader_size;
		u8 reserved2[0x4];
		struct sFlags
		{
			u8 reserved[3];
			u8 key_x_index;
			u8 platform;
			u8 content_type;
			u8 block_size;
			u8 other_flag;
		} flags;
		sSectionGeometry plain_region;
		sSectionGeometry logo;
		sSectionGeometry exefs;
		u32 exefs_hashed_data_size;
		u8 reserved3[4];
		sSectionGeometry romfs;
		u32 romfs_hashed_data_size;
		u8 reserved4[4];
		u8 exefs_hash[Crypto::kSha256HashLen];
		u8 romfs_hash[Crypto::kSha256HashLen];
		
	};

	struct sNcchHeader header_;
	u32 access_descriptor_size_;

	inline u32 block_size() const { return 1 << (header_.flags.block_size + 9); }
	inline u32 size_to_block(u64 size) const { return (u32)(align(size, block_size()) >> (header_.flags.block_size + 9)); }
	inline u64 block_to_size(u32 block_num) const { return ((u64)block_num) << (header_.flags.block_size + 9); }
};

