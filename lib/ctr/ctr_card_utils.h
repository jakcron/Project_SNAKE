#pragma once
#include "ncsd_header.h"
#include "cci_cardinfo_header.h"

class CtrCardUtils
{
public:
	enum ErrorCode
	{
		ERR_NOERROR,
		ERR_INVALID_SAVE_SIZE,
		ERR_CONTENT_TOO_LARGE,
		ERR_MEDIA_NOT_SUPPORT_SIZE,
		ERR_NONSTANDARD_WRITABLE_ADDRESS,
	};

	enum UnitSize : u64
	{
		UNIT_B = BIT(0),
		UNIT_KB = BIT(10),
		UNIT_MB = BIT(20),
		UNIT_GB = BIT(30)
	};

	enum CtrCardSize : u64
	{
		CARD_128MB = 128 * UNIT_MB,
		CARD_256MB = 256 * UNIT_MB,
		CARD_512MB = 512 * UNIT_MB,
		CARD_1GB = 1 * UNIT_GB,
		CARD_2GB = 2 * UNIT_GB,
		CARD_4GB = 4 * UNIT_GB,
		CARD_8GB = 8 * UNIT_GB,
	};

	CtrCardUtils();
	~CtrCardUtils();

	void GetSuitableRomConfigureation(u64 total_content_size, u32 save_data_size, NcsdHeader::MediaType& media_type, NcsdHeader::CardDevice& card_device, CtrCardSize& rom_size, u64& writable_address);

	u64 GetWritableAddress(CtrCardSize card_size, NcsdHeader::MediaType media_type, u32 save_size);
	u64 GetUnusedSize(CtrCardSize card_size, NcsdHeader::MediaType media_type);

	CtrCardSize GetSuitableCardSize(u64 total_content_size, NcsdHeader::MediaType media_type);
	CtrCardSize GetNextCardSize(CtrCardSize card_size);

	int GetCard2SaveSizeFromWritableAddress(CtrCardSize card_size, u64 writeable_address, u32& save_size) noexcept;

private:
	const char *kModuleName = "CTR_CARD_UTILS";

	enum Card1UnusedSize
	{
		CARD1_128MB_UNUSED = 0x280000,
		CARD1_256MB_UNUSED = 0x500000,
		CARD1_512MB_UNUSED = 0xA00000,
		CARD1_1GB_UNUSED = 0x4680000,
		CARD1_2GB_UNUSED = 0x8C80000,
		CARD1_4GB_UNUSED = 0x11900000,
		CARD1_8GB_UNUSED = 0x23000000,
	};

	enum Card2UnusedSize
	{
		CARD2_512MB_UNUSED = 0x2380000,
		CARD2_1GB_UNUSED = 0x4680000,
		CARD2_2GB_UNUSED = 0x8C80000,
		CARD2_4GB_UNUSED = 0x11900000,
		CARD2_8GB_UNUSED = 0x23000000,
	};

	void ValidateSaveDataSize(NcsdHeader::MediaType media_type, u32 save_data_size);	
};

