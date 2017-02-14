#pragma once
#include <fnd/types.h>
#include <fnd/memory_blob.h>
#include <ctr/ncch_header.h>

class CardInfoHeader
{
public:
	enum CardType
	{
		CARD_TYPE_S1,
		CARD_TYPE_S2,
	};

	static const int kReservedRegionSize = 0xD00;

	CardInfoHeader();
	CardInfoHeader(const u8* data);
	CardInfoHeader(const CardInfoHeader& other);
	~CardInfoHeader();

	void operator=(const CardInfoHeader& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Header Serialisation
	void SerialiseHeader();
	void SetWritableOffset(u32 offset);
	void SetCardType(CardType type);
	void SetCryptoType(u8 type); // 0-3 inclusive
	void SetReservedRegion(const u8* data, u32 size);
	void SetCardSeedData(const u8 key_y[Crypto::kAes128KeySize], const u8 encrypted_seed[Crypto::kAes128KeySize], const u8 mac[Crypto::kAesBlockSize], const u8 nonce[Crypto::KAesCcmNonceSize]);

	// Header Deserialisation
	void DeserialiseHeader(const u8* data);
	u32 GetWritableOffset() const;
	CardType GetCardType() const;
	u8 GetCryptoType() const;
	const u8* GetReservedRegion() const;
	const u8* GetSeedKeyY() const;
	const u8* GetEncryptedSeed() const;
	const u8* GetSeedMac() const;
	const u8* GetSeedNonce() const;


private:
	const std::string kModuleName = "CARD_INFO_HEADER";
	static const int kNcchHeaderSize = 0x100;
	static const int kCardTypeShift = 5;
	static const u32 kCardTypeMask = 1;
	static const int kCryptoTypeShift = 6;
	static const u32 kCryptoTypeMask = 3;

#pragma pack (push, 1)
	struct sCardInfoHeader
	{
	private:
		u32 writable_offset_;
		u32 flags_; // bit5 CardType(s1=0,s2=1), bit6-7 CryptoType(0-3)
		u8 padding0[0xf8];
		u8 reserved_region_[kReservedRegionSize];
		struct sCardSeedData {
			u8 key_y[Crypto::kAes128KeySize];
			u8 encrypted_seed[Crypto::kAes128KeySize];
			u8 mac[Crypto::kAesBlockSize];
			u8 nonce[Crypto::KAesCcmNonceSize];
		} card_seed_;
		u8 padding1[0xc4];
		u8 ncch_header_[kNcchHeaderSize];
	public:
		u32 writable_offset() const { return le_word(writable_offset_); }
		//u32 flags() const { return be_word(flags_); }
		CardType card_type() const { return (CardType)((be_word(flags_) >> kCardTypeShift) & kCardTypeMask); }
		u8 crypto_type() const { return (u8)((be_word(flags_) >> kCryptoTypeShift) & kCryptoTypeMask); }
		bool has_unsupported_flag() const { return (be_word(flags_) & ~((kCardTypeMask << kCardTypeShift) | (kCryptoTypeMask << kCryptoTypeShift))) != 0; }
		const u8* reserved_region() const { return reserved_region_; }
		const u8* seed_key_y() const { return card_seed_.key_y; }
		const u8* encrypted_seed() const { return card_seed_.encrypted_seed; }
		const u8* seed_mac() const { return card_seed_.mac; }
		const u8* seed_nonce() const { return card_seed_.nonce; }
		const u8* ncch_header() const { return ncch_header_; }

		void clear() { memset(this, 0, sizeof(sCardInfoHeader)); }

		void set_writable_offset(u32 offset) { writable_offset_ = le_word(offset); }
		//void set_flags(u32 flags) { flags_ = flags; }
		void set_card_type(CardType type) { flags_ &= be_word(~(kCardTypeMask << kCardTypeShift)); flags_ |= be_word((type & kCardTypeMask) << kCardTypeShift); }
		void set_crypto_type(u8 type) { flags_ &= be_word(~(kCryptoTypeMask << kCryptoTypeShift)); flags_ |= be_word((type & kCryptoTypeMask) << kCryptoTypeShift); }
		void set_reserved_region(const u8* data, u32 size) { memcpy(reserved_region_, data, size < kReservedRegionSize ? size : kReservedRegionSize); }
		void set_card_seed_data(const u8 encrypted_seed[Crypto::kAes128KeySize], const u8 key_y[Crypto::kAes128KeySize], const u8 mac[Crypto::kAesBlockSize], const u8 nonce[Crypto::KAesCcmNonceSize]) 
		{
			memcpy(card_seed_.encrypted_seed, encrypted_seed, Crypto::kAes128KeySize);
			memcpy(card_seed_.key_y, key_y, Crypto::kAes128KeySize);
			memcpy(card_seed_.mac, mac, Crypto::kAesBlockSize);
			memcpy(card_seed_.nonce, nonce, Crypto::KAesCcmNonceSize);
		}
		void set_ncch_header(const u8* data) { memcpy(ncch_header_, data, kNcchHeaderSize); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	u32 writable_offset_;
	CardType card_type_;
	u8 crypto_type_;
	u8 reserved_region_[kReservedRegionSize];
	u8 key_y_[Crypto::kAes128KeySize];
	u8 encrypted_seed_[Crypto::kAes128KeySize];
	u8 mac_[Crypto::kAesBlockSize];
	u8 nonce_[Crypto::KAesCcmNonceSize];
	NcchHeader ncch_header_;

	void ClearDeserialisedVariables();
};

