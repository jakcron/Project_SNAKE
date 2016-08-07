#pragma once
#include "types.h"

class NcsdCardInfoHeader
{
public:
	NcsdCardInfoHeader();
	~NcsdCardInfoHeader();
	

private:
	const u8 stock_card_seed_mac[0x30] =
	{
		0xAD, 0x88, 0xAC, 0x41, 0xA2, 0xB1, 0x5E, 0x8F, 0x66, 0x9C, 0x97, 0xE5, 0xE1, 0x5E, 0xA3, 0xEB
	};

	const u8 stock_title_key[0x10] =
	{
		0x6E, 0xC7, 0x5F, 0xB2, 0xE2, 0xB4,	0x87, 0x46, 0x1E, 0xDD, 0xCB, 0xB8, 0x97, 0x11, 0x92, 0xBA
	};

	struct CardInfoHeader {
		u32 writable_offset = le_word(((u32)-1));
		u32 flags;
		u8 reserved0[0xf8];
		struct ProductionRomData {
			u64 total_used_size;
			u8 reserved0[8];
			u32 unknown;
			u8 reserved1[12];
			u64 cver_title_id;
			u16 cver_title_version;
		} prod_data;
		u8 reserved1[0xcd6];
		u8 card_seed_key_y[0x10];
		u8 encrypted_card_seed[0x10];
		u8 card_seed_mac[0x10];
		u8 card_seed_nonce[0xc];
		u8 reserved2[0xc4];
		u8 ncch_header[0x100];
	};

	struct CardInfoHeaderDevelopmentExtention {
		u8 reserved0[0x200];
		u8 title_key[0x10];
		u8 reserved1[0xf0];
	};
};
