#include "card_info_header.h"



CardInfoHeader::CardInfoHeader()
{
	ClearDeserialisedVariables();
}

CardInfoHeader::CardInfoHeader(const u8 * data)
{
	DeserialiseHeader(data);
}

CardInfoHeader::CardInfoHeader(const CardInfoHeader & other)
{
	DeserialiseHeader(other.GetSerialisedData());
}


CardInfoHeader::~CardInfoHeader()
{
}

void CardInfoHeader::operator=(const CardInfoHeader & other)
{
	this->DeserialiseHeader(other.GetSerialisedData());
}

const u8 * CardInfoHeader::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t CardInfoHeader::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void CardInfoHeader::SerialiseHeader()
{
	// allocate memory for header
	if (serialised_data_.alloc(sizeof(sCardInfoHeader)))
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for card info header");
	}

	sCardInfoHeader* hdr = (sCardInfoHeader*)(serialised_data_.data());

	hdr->set_writable_offset(writable_offset_);
	hdr->set_card_type(card_type_);
	hdr->set_crypto_type(crypto_type_);
	hdr->set_reserved_region(reserved_region_, kReservedRegionSize);
	hdr->set_card_seed_data(encrypted_seed_, key_y_, mac_, nonce_);
	
	if (ncch_header_.GetSerialisedDataSize() == 0x200)
	{
		hdr->set_ncch_header(ncch_header_.GetSerialisedData() + 0x100);
	}
}

void CardInfoHeader::SetWritableOffset(u32 offset)
{
	writable_offset_ = offset;
}

void CardInfoHeader::SetCardType(CardType type)
{
	card_type_ = type;
}

void CardInfoHeader::SetCryptoType(u8 type)
{
	crypto_type_ = type;
}

void CardInfoHeader::SetReservedRegion(const u8 * data, u32 size)
{
	memcpy(reserved_region_, data, size < kReservedRegionSize ? size : kReservedRegionSize);
}

void CardInfoHeader::SetCardSeedData(const u8 key_y[Crypto::kAes128KeySize], const u8 encrypted_seed[Crypto::kAes128KeySize], const u8 mac[Crypto::kAesBlockSize], const u8 nonce[Crypto::KAesCcmNonceSize])
{
	memcpy(key_y_, key_y, Crypto::kAes128KeySize);
	memcpy(encrypted_seed_, encrypted_seed, Crypto::kAes128KeySize);
	memcpy(mac_, mac, Crypto::kAesBlockSize);
	memcpy(nonce_, nonce, Crypto::KAesCcmNonceSize);
}

void CardInfoHeader::DeserialiseHeader(const u8 * data)
{
	ClearDeserialisedVariables();
	// allocate memory for header
	if (serialised_data_.alloc(sizeof(sCardInfoHeader)))
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for card info header");
	}

	// save data
	memcpy(serialised_data_.data(), data, sizeof(sCardInfoHeader));

	// get pointer
	const sCardInfoHeader* hdr = (const sCardInfoHeader*)(serialised_data_.data());

	if (hdr->has_unsupported_flag())
	{
		throw ProjectSnakeException(kModuleName, "Card info header has unsupported flags");
	}

	writable_offset_ = hdr->writable_offset();
	card_type_ = hdr->card_type();
	crypto_type_ = hdr->crypto_type();
	memcpy(reserved_region_, hdr->reserved_region(), kReservedRegionSize);
	memcpy(key_y_, hdr->seed_key_y(), Crypto::kAes128KeySize);
	memcpy(encrypted_seed_, hdr->encrypted_seed(), Crypto::kAes128KeySize);
	memcpy(mac_, hdr->seed_mac(), Crypto::kAesBlockSize);
	memcpy(nonce_, hdr->seed_nonce(), Crypto::KAesCcmNonceSize);
	
	// try to deserialise the ncch header
	try 
	{
		u8 ncch_header[0x200];
		memcpy(ncch_header + 0x100, hdr->ncch_header(), kNcchHeaderSize);
		ncch_header_.DeserialiseHeader(ncch_header);
	}
	catch (const ProjectSnakeException& e)
	{
		throw ProjectSnakeException(kModuleName, e.what());
	}

}

u32 CardInfoHeader::GetWritableOffset() const
{
	return writable_offset_;
}

CardInfoHeader::CardType CardInfoHeader::GetCardType() const
{
	return card_type_;
}

u8 CardInfoHeader::GetCryptoType() const
{
	return crypto_type_;
}

const u8 * CardInfoHeader::GetReservedRegion() const
{
	return reserved_region_;
}

const u8 * CardInfoHeader::GetSeedKeyY() const
{
	return key_y_;
}

const u8 * CardInfoHeader::GetEncryptedSeed() const
{
	return encrypted_seed_;
}

const u8 * CardInfoHeader::GetSeedMac() const
{
	return mac_;
}

const u8 * CardInfoHeader::GetSeedNonce() const
{
	return nonce_;
}

void CardInfoHeader::ClearDeserialisedVariables()
{
	writable_offset_ = 0;
	card_type_ = CardType::CARD_TYPE_S1;
	crypto_type_ = 0;
	memset(reserved_region_, 0, kReservedRegionSize);
	memset(key_y_, 0, Crypto::kAes128KeySize);
	memset(encrypted_seed_, 0, Crypto::kAes128KeySize);
	memset(mac_, 0, Crypto::kAesBlockSize);
	memset(nonce_, 0, Crypto::KAesCcmNonceSize);
	ncch_header_ = NcchHeader();
}
