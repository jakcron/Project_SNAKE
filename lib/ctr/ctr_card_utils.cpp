#include "ctr_card_utils.h"



CtrCardUtils::CtrCardUtils()
{
}


CtrCardUtils::~CtrCardUtils()
{
}

void CtrCardUtils::GetSuitableRomConfigureation(u64 current_rom_size, u32 save_data_size, NcsdHeader::MediaType & media_type, NcsdHeader::CardDevice & card_device, CtrCardSize & rom_size, u64 & writable_address)
{
	if (save_data_size < UNIT_MB)
	{
		// for save sizes less that 1MB, the media type is CARD1
		media_type = NcsdHeader::MEDIA_TYPE_CARD1;

		// if there is save data, we need to use a NOR FLASH
		if (save_data_size > 0)
		{
			card_device = NcsdHeader::CARD_DEVICE_NOR_FLASH;
		}

		// no save data, has no additional card device
		else
		{
			card_device = NcsdHeader::CARD_DEVICE_NONE;
		}
	}
	else
	{
		media_type = NcsdHeader::MEDIA_TYPE_CARD2;
		card_device = NcsdHeader::CARD_DEVICE_NONE;
	}

	ValidateSaveDataSize(media_type, save_data_size); // will throw an exception if the savedata size is bad

	rom_size = GetSuitableCardSize(current_rom_size, media_type);
	writable_address = GetWritableAddress(rom_size, media_type, save_data_size);

	// if the writable address position is some how before the end of the used cci data
	while (writable_address < current_rom_size)
	{
		rom_size = GetNextCardSize(rom_size); // this will throw an exception if the card size upper limit is reached
		writable_address = GetWritableAddress(rom_size, media_type, save_data_size);
	}
}

u64 CtrCardUtils::GetWritableAddress(CtrCardSize card_size, NcsdHeader::MediaType media_type, u32 save_size)
{
	u64 writable_address = 0xffffffffffffffff;

	if (media_type == NcsdHeader::MEDIA_TYPE_CARD2)
	{
		ValidateSaveDataSize(media_type, save_size);
		writable_address = card_size - GetUnusedSize(card_size, NcsdHeader::MEDIA_TYPE_CARD2) - save_size;
	}

	return writable_address;
}

u64 CtrCardUtils::GetUnusedSize(CtrCardSize card_size, NcsdHeader::MediaType media_type)
{
	u64 unused_size = 0;

	if (media_type == NcsdHeader::MEDIA_TYPE_CARD1)
	{
		switch (card_size)
		{
		case(CARD_128MB) : 
			unused_size = CARD1_128MB_UNUSED;
			break;
		case(CARD_256MB):
			unused_size = CARD1_256MB_UNUSED;
			break;
		case(CARD_512MB):
			unused_size = CARD1_512MB_UNUSED;
			break;
		case(CARD_1GB):
			unused_size = CARD1_1GB_UNUSED;
			break;
		case(CARD_2GB):
			unused_size = CARD1_2GB_UNUSED;
			break;
		case(CARD_4GB):
			unused_size = CARD1_4GB_UNUSED;
			break;
		case(CARD_8GB):
			unused_size = CARD1_8GB_UNUSED;
			break;
		default:
			throw ProjectSnakeException(kModuleName, "CARD1 only supports the following card sizes: 128MB, 256MB, 512MB, 1GB, 2GB, 4GB, 8GB");
		}
	}
	else if (media_type == NcsdHeader::MEDIA_TYPE_CARD2)
	{
		switch (card_size)
		{
		case(CARD_512MB):
			unused_size = CARD2_512MB_UNUSED;
			break;
		case(CARD_1GB):
			unused_size = CARD2_1GB_UNUSED;
			break;
		case(CARD_2GB):
			unused_size = CARD2_2GB_UNUSED;
			break;
		case(CARD_4GB):
			unused_size = CARD2_4GB_UNUSED;
			break;
		case(CARD_8GB):
			unused_size = CARD2_8GB_UNUSED;
			break;
		default:
			throw ProjectSnakeException(kModuleName, "CARD2 only supports the following card sizes: 512MB, 1GB, 2GB, 4GB, 8GB");
		}
	}
	return unused_size;
}

CtrCardUtils::CtrCardSize CtrCardUtils::GetSuitableCardSize(u64 total_content_size, NcsdHeader::MediaType media_type)
{
	CtrCardSize suitable_size = CARD_128MB;

	if (media_type != NcsdHeader::MEDIA_TYPE_CARD2 && total_content_size < GetUnusedSize(CARD_128MB, media_type))
	{
		suitable_size = CARD_128MB;
	}
	else if (media_type != NcsdHeader::MEDIA_TYPE_CARD2 && total_content_size < GetUnusedSize(CARD_256MB, media_type))
	{
		suitable_size = CARD_256MB;
	}
	else if (total_content_size < GetUnusedSize(CARD_512MB, media_type))
	{
		suitable_size = CARD_512MB;
	}
	else if (total_content_size < GetUnusedSize(CARD_1GB, media_type))
	{
		suitable_size = CARD_1GB;
	}
	else if (total_content_size < GetUnusedSize(CARD_2GB, media_type))
	{
		suitable_size = CARD_2GB;
	}
	else if (total_content_size < GetUnusedSize(CARD_4GB, media_type))
	{
		suitable_size = CARD_4GB;
	}
	else if (total_content_size < GetUnusedSize(CARD_8GB, media_type))
	{
		suitable_size = CARD_8GB;
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Current CCI image is too large for physical media");
	}

	return suitable_size;
}

CtrCardUtils::CtrCardSize CtrCardUtils::GetNextCardSize(CtrCardSize card_size)
{
	CtrCardSize new_size = CARD_128MB;

	if (card_size < CARD_256MB)
	{
		new_size = CARD_256MB;
	}
	else if (card_size < CARD_512MB)
	{
		new_size = CARD_512MB;
	}
	else if (card_size < CARD_1GB)
	{
		new_size = CARD_1GB;
	}
	else if (card_size < CARD_2GB)
	{
		new_size = CARD_2GB;
	}
	else if (card_size < CARD_4GB)
	{
		new_size = CARD_4GB;
	}
	else if (card_size < CARD_8GB)
	{
		new_size = CARD_8GB;
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Current CCI image is too large for physical media");
	}

	return new_size;
}

int CtrCardUtils::GetCard2SaveSizeFromWritableAddress(CtrCardSize card_size, u64 writeable_address, u32& save_size) noexcept
{
	u64 unused_size = GetUnusedSize(card_size, NcsdHeader::MEDIA_TYPE_CARD2);
	u64 end_of_writable_region = card_size - unused_size;
	u64 used_writable_region = end_of_writable_region - writeable_address;

	// this is limited to 2GB, so if it's greater the save size cannot be predicted
	if (used_writable_region > (2 * UNIT_GB))
	{
		return ERR_NONSTANDARD_WRITABLE_ADDRESS;
	}

	save_size = (u32)used_writable_region;

	return ERR_NOERROR;
}

void CtrCardUtils::ValidateSaveDataSize(NcsdHeader::MediaType media_type, u32 save_data_size)
{
	if (media_type == NcsdHeader::MEDIA_TYPE_CARD1)
	{
		if (save_data_size != (128 * UNIT_KB) && save_data_size != (512 * UNIT_KB) && save_data_size != 0)
		{
			throw ProjectSnakeException(kModuleName, "Save sizes for CARD1 must be 128K or 512K");
		}
	}
	if (media_type == NcsdHeader::MEDIA_TYPE_CARD2)
	{
		if ((save_data_size % UNIT_MB) != 0 || save_data_size >= (2 * UNIT_GB))
		{
			throw ProjectSnakeException(kModuleName, "Save sizes for CARD2 must be aligned to 1MB and be less than 2048MB");
		}
	}
	
}
