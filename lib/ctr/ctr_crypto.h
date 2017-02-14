#pragma once
#include <fnd/types.h>
#include <crypto/crypto.h>
#include <ctr/ncch_header.h>

class CtrCrypto
{
public:
	enum NcchSectionType
	{
		SECTION_EXHEADER = 1,
		SECTION_EXEFS,
		SECTION_ROMFS,
	};

	static void SetupNcchCtr(uint64_t title_id, NcchSectionType section_type, NcchHeader::FormatVersion format, uint8_t ctr[Crypto::kAesBlockSize]);
	static void KeyGenerator(const uint8_t key_x[Crypto::kAes128KeySize], const uint8_t key_y[Crypto::kAes128KeySize], uint8_t key[Crypto::kAes128KeySize]);

};

