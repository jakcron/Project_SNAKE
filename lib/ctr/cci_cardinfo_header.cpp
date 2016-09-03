#include <cstring>
#include <cstdio>
#include "cci_cardinfo_header.h"

CciCardInfoHeader::CciCardInfoHeader()
{
	Clear();
}

CciCardInfoHeader::~CciCardInfoHeader()
{
	Clear();
}

void CciCardInfoHeader::SetWritableAddress(u32 block_offset)
{
	header()->writable_offset = le_word(block_offset);
}

void CciCardInfoHeader::SetCardType(CardType type)
{
	header()->flags &= be_word(~(0x3f));
	header()->flags |= be_word(type & 0x3f);
}

void CciCardInfoHeader::SetCryptoType(u8 type)
{
	header()->flags &= be_word(~(0x3 << kCryptoTypeBitShift));
	header()->flags |= be_word((type & 0x3) << kCryptoTypeBitShift);
}

void CciCardInfoHeader::SetDevelopmentExtendedHeader(const u8 title_key[Crypto::kAes128KeySize])
{
	memset(dev_extent(), 0, sizeof(CardInfoHeaderDevelopmentExtension));
	memcpy(dev_extent()->title_key, title_key, Crypto::kAes128KeySize);
}

void CciCardInfoHeader::Clear()
{
	memset(raw_buffer_, 0, kDataSize);
}

void CciCardInfoHeader::SetCciUsedSize(u64 used_size)
{
	header()->cci_size_data.used_size = le_dword(used_size);
}

void CciCardInfoHeader::SetUnknownValue(u32 unknown)
{
	header()->unknown_data.unknown = le_word(unknown);
}

void CciCardInfoHeader::SetCverTitleInfo(u64 title_id, u16 version)
{
	header()->cver_data.title_id = le_dword(title_id);
	header()->cver_data.version = le_hword(version);
}

void CciCardInfoHeader::SetCardSeedData(const u8 card_seed_key_y[Crypto::kAes128KeySize], const u8 encrypted_card_seed[Crypto::kAes128KeySize], const u8 card_seed_mac[Crypto::kAesBlockSize], const u8 card_seed_nonce[Crypto::KAesCcmNonceSize])
{
	memcpy(header()->card_seed.seed_key_y, card_seed_key_y, Crypto::kAes128KeySize);
	memcpy(header()->card_seed.encrypted_seed, encrypted_card_seed, Crypto::kAes128KeySize);
	memcpy(header()->card_seed.mac, card_seed_mac, Crypto::kAesBlockSize);
	memcpy(header()->card_seed.nonce, card_seed_nonce, Crypto::KAesCcmNonceSize);
}

void CciCardInfoHeader::SetNcchHeader(const NcchHeader& ncch_header)
{
	memcpy(header()->ncch_header, ncch_header.header_blob() + 0x100, 0x100);
}

void CciCardInfoHeader::SetCardInfoHeader(const u8* card_info_header)
{
	SetCardInfoHeader(card_info_header, kDataSize);
}

void CciCardInfoHeader::SetCardInfoHeader(const u8 * card_info_header, u32 size)
{
	u32 copy_len = size > kDataSize ? kDataSize : size;
	memcpy(raw_buffer_, card_info_header, copy_len);
}

void CciCardInfoHeader::InitialiseAsCtrSdkCci(u64 title_id)
{
	SetWritableAddress(0xffffffff);
	SetCardType(CARD_TYPE_S1);
	SetCryptoType(3);

	u8 seed_key_y[Crypto::kAes128KeySize];
	// write the title id as little endian to the key_y
	memset(seed_key_y, 0, Crypto::kAes128KeySize);
	for (int i = 0; i < 8; i++) {
		seed_key_y[i] = (title_id >> (i * 8)) & 0xff;
	}

	SetCardSeedData(seed_key_y, kCtrSdkEncryptedCardSeed, kCtrSdkCardSeedMac, kCtrSdkCardSeedNonce);

	// use extended header data
	SetDevelopmentExtendedHeader(kCtrSdkTitleKey);
}
