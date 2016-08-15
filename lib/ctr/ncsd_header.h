#pragma once
#include "types.h"
#include "crypto.h"

class NcsdHeader
{
public:
	enum ErrorCode
	{
		ERR_NOERROR,
		ERR_SIGN_FAIL,
		ERR_CORRUPT_DATA,
	};

	enum SectionFsType
	{
		FS_TYPE_NONE = 0,
	};

	enum SectionCryptoType
	{
		CRYPTO_TYPE_NONE = 0,
	};

	enum CardDevice 
	{
		CARD_DEVICE_NOR_FLASH = 1,
		CARD_DEVICE_NONE = 2,
		CARD_DEVICE_BT = 3,
	};

	enum Platform 
	{
		CTR = 1,
		SNAKE = 2,
	};

	enum MediaType 
	{
		MEDIA_TYPE_INNER_DEVICE = 0, //NAND
		MEDIA_TYPE_CARD1 = 1,
		MEDIA_TYPE_CARD2 = 2,
		MEDIA_TYPE_EXTENDED_DEVICE = 3,
	};

	enum NcsdSectionReservation
	{
		SECTION_EXEC = 0,
		SECTION_EMANUAL = 1,
		SECTION_DLP_CHILD = 2,
		SECTION_SNAKE_UPDATE = 6,
		SECTION_CTR_UPDATE = 7,
	};

	static const int kSectionNum = 8;

	NcsdHeader();
	~NcsdHeader();

	// create + sign header
	int CreateHeader(const Crypto::sRsa2048Key& ncsd_rsa_key);
	inline const u8* header_blob() const { return (u8*)&header_; }
	inline u32 header_size() const { return sizeof(struct sNcsdHeader); }

	// Set header for parsing ncsd headers
	int SetHeader(const u8* header);
	int ValidateHeaderSignature(const Crypto::sRsa2048Key& ncsd_rsa_key);

	// Basic Data
	void SetTitleId(u64 title_id);

	// Flags
	void SetCardDevice(CardDevice device);
	void SetPlatform(Platform platform);
	void SetMediaType(MediaType type);
	void SetBlockSize(u32 size);

	// Data segments
	void SetSection(u8 index, SectionFsType fs_type, SectionCryptoType crypto_type, u64 size);
	void SetSection(u8 index, u64 size);
	void SetCardInfoHeader(u32 size);
	void FinaliseNcsdLayout();

	// Get data from header
	inline u64 title_id() const { return le_dword(header_.title_id); }
	inline u64 ncsd_size() const { return block_to_size(le_word(header_.size)); }
	inline SectionFsType section_fs(u8 section) const { return (SectionFsType)(section < kSectionNum ? header_.section_fs_type[section] : FS_TYPE_NONE); }
	inline SectionCryptoType section_crypto(u8 section) const { return (SectionCryptoType)(section < kSectionNum ? header_.section_fs_type[section] : CRYPTO_TYPE_NONE); }
	inline u64 section_offset(u8 section) const { return section < kSectionNum ? block_to_size(le_word(header_.section_location[section].offset)) : 0; }
	inline u64 section_size(u8 section) const { return section < kSectionNum ? block_to_size(le_word(header_.section_location[section].size)) : 0; }
	inline CardDevice card_device() const { return (CardDevice)(header_.flags.card_device_old > 0 ? header_.flags.card_device_old : header_.flags.card_device); }
	inline MediaType media_type() const { return (MediaType)(header_.flags.media_type); }
	inline Platform platform() const { return (Platform)(header_.flags.platform); }

private:
	const char kMagic[4] = { 'N', 'C', 'S', 'D' };
	static const uint32_t kDefaultBlockSize = 0x200;
	static const uint32_t kDefaultNcchOffset = 0x4000;

	struct sSectionGeometry
	{
		u32 offset;
		u32 size;
	};

	struct sNcsdHeader
	{
		u8 signature[Crypto::kRsa2048Size];
		char magic[4];
		u32 size;
		u64 title_id;
		u8 section_fs_type[kSectionNum];
		u8 section_crypto_type[kSectionNum];
		sSectionGeometry section_location[kSectionNum];
		u8 extended_header_hash[Crypto::kSha256HashLen];
		u32 additional_header_size;
		u32 sector0_offset;
		struct sFlags{
			u8 backup_write_wait_time;
			u8 backup_security_type;
			u8 reserved1;
			u8 card_device;
			u8 platform;
			u8 media_type;
			u8 block_size;
			u8 card_device_old;
		} flags;
		u64 ncch_titleid_table[kSectionNum];
		u8 reserved1[0x30];
	};

	struct sNcsdHeader header_;
	u32 card_info_header_size_;

	inline u32 block_size() const { return 1 << (header_.flags.block_size + 9); }
	inline u32 size_to_block(u64 size) const { return (u32)(align(size, block_size()) >> (header_.flags.block_size + 9)); }
	inline u64 block_to_size(u32 block_num) const { return ((u64)block_num) << (header_.flags.block_size + 9); }
};
