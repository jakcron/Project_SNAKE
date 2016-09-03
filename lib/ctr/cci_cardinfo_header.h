#pragma once
#include "types.h"
#include "crypto.h"

#include "ncch_header.h"

class CciCardInfoHeader
{
public:
	enum CardType
	{
		CARD_TYPE_S1 = 0,
		CARD_TYPE_S2 = BIT(5),
	};

	CciCardInfoHeader();
	~CciCardInfoHeader();
	
	inline const u8* data_blob() const { return raw_buffer_; }
	inline u32 data_size() const { return kDataSize; }

	// Set from existing data
	void SetCardInfoHeader(const u8* card_info_header);
	void SetCardInfoHeader(const u8* card_info_header, u32 size);

	// initialise CardInfoHeader using CTR-SDK defaults 
	void InitialiseAsCtrSdkCci(u64 title_id);

	// Set Card Info
	void SetWritableAddress(u32 block_offset); // start of writable region for CARD2 gamecards
	void SetCardType(CardType type); // Unknown what this does
	void SetCryptoType(u8 type); // 0-3 Unknown what this does

	void SetCciUsedSize(u64 used_size);
	void SetUnknownValue(u32 unknown);
	void SetCverTitleInfo(u64 title_id, u16 version);

	void SetCardSeedData(const u8 card_seed_key_y[Crypto::kAes128KeySize], const u8 encrypted_card_seed[Crypto::kAes128KeySize], const u8 card_seed_mac[Crypto::kAesBlockSize], const u8 card_seed_nonce[Crypto::KAesCcmNonceSize]);
	void SetNcchHeader(const NcchHeader& ncch_header);
	void SetDevelopmentExtendedHeader(const u8 title_key[Crypto::kAes128KeySize]);	// extend the card info header to include a title_key (seen only in devkit roms)

	// Get Card Info
	inline u32 writable_offset() const { return le_word(header_const()->writable_offset); }
	inline bool is_writable_offset_valid() const { return writable_offset() != kDefaultWritableOffset; }
	inline CardType card_type() const { return (CardType)(be_word(header_const()->flags) & 0x3f); }
	inline u8 crypto_type() const { return (be_word(header_const()->flags) >> kCryptoTypeBitShift) & kMaxCryptoType; }
	inline u64 cci_used_size() const {return le_dword(header_const()->cci_size_data.used_size); }
	inline u64 cver_title_id() const { return le_dword(header_const()->cver_data.title_id); }
	inline u16 cver_title_version() const { return le_hword(header_const()->cver_data.version); }

private:
	static const u32 kDataSize = 0x4000 - 0x200;
	static const u32 kDefaultWritableOffset = 0xffffffff;
	static const int kCryptoTypeBitShift = 6;
	static const int kMaxCryptoType = 3;

	const u8 kCtrSdkEncryptedCardSeed[Crypto::kAes128KeySize] =
	{ 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	const u8 kCtrSdkCardSeedMac[Crypto::kAesBlockSize] =
	{
		0xAD, 0x88, 0xAC, 0x41, 0xA2, 0xB1, 0x5E, 0x8F, 0x66, 0x9C, 0x97, 0xE5, 0xE1, 0x5E, 0xA3, 0xEB
	};

	const u8 kCtrSdkCardSeedNonce[Crypto::KAesCcmNonceSize] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	const u8 kCtrSdkTitleKey[Crypto::kAes128KeySize] =
	{
		0x6E, 0xC7, 0x5F, 0xB2, 0xE2, 0xB4,	0x87, 0x46, 0x1E, 0xDD, 0xCB, 0xB8, 0x97, 0x11, 0x92, 0xBA
	};

#pragma pack(push, 1)
	struct CardInfoHeader {
		u32 writable_offset = kDefaultWritableOffset;
		u32 flags;
		u8 reserved0[0xf8];

		struct CciSizeData {
			u64 used_size;
			u8 padding[0x8];
		} cci_size_data;
		
		struct UnknownInfo {
			u32 unknown;
			u8 padding[0xC];
		} unknown_data;

		struct CverDataInfo {
			u64 title_id;
			u16 version;
			u8 padding[0x6];
		} cver_data;
		u8 reserved1[0xcd0];

		struct CardSeedData {
			u8 seed_key_y[Crypto::kAes128KeySize];
			u8 encrypted_seed[Crypto::kAes128KeySize];
			u8 mac[Crypto::kAesBlockSize];
			u8 nonce[Crypto::KAesCcmNonceSize];
			u8 reserved[4];
		} card_seed;
		u8 reserved2[0xc0];

		u8 ncch_header[0x100];
	};

	struct CardInfoHeaderDevelopmentExtension {
		u8 reserved0[0x200];
		u8 title_key[0x10];
		u8 reserved1[0xf0];
	};
#pragma pack(pop)

	u8 raw_buffer_[kDataSize];

	void Clear();

	inline CardInfoHeader* header() { return (CardInfoHeader*)raw_buffer_; }
	inline const CardInfoHeader* header_const() const { return (CardInfoHeader*)raw_buffer_; }
	inline CardInfoHeaderDevelopmentExtension* dev_extent() { return (CardInfoHeaderDevelopmentExtension*)(raw_buffer_+sizeof(CardInfoHeader)); }
};
