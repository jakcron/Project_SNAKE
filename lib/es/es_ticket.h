#pragma once
#include <vector>
#include "types.h"
#include "ByteBuffer.h"
#include "crypto.h"

class EsTicket
{
public:
	enum ESLicenseType
	{
		ES_LICENSE_PERMANENT = 0,
		ES_LICENSE_DEMO = 1,
		ES_LICENSE_TRIAL = 2,
		ES_LICENSE_RENTAL = 3,
		ES_LICENSE_SUBSCRIPTION = 4,
		ES_LICENSE_SERVICE = 5,
		ES_LICENSE_MASK = 15,
	};

	enum ESLimitCode
	{
		ES_LC_DURATION_TIME = 1,
		ES_LC_ABSOLUTE_TIME = 2,
		ES_LC_NUM_TITLES = 3,
		ES_LC_NUM_LAUNCH = 4,
		ES_LC_ELAPSED_TIME = 5,
		ES_MAX_LIMIT_TYPE = 8,
	};

	EsTicket();
	~EsTicket();

	// this also signs the ticket
	int CreateTicket(const char* signature_issuer, const u8 rsa_modulus[Crypto::kRsa2048Size], const u8 rsa_priv_exponent[Crypto::kRsa2048Size]);

	inline const u8* data_blob() const { return ticket_.data_const(); }
	inline u32 data_size() const { return ticket_.size(); }

	void SetTitleKey(const u8 title_key[Crypto::kAes128KeySize], const u8 common_key[Crypto::kAes128KeySize], u8 common_key_index);
	void SetEncryptedTitleKey(const u8 title_key[Crypto::kAes128KeySize], u8 common_key_index);
	void SetTicketId(u64 ticket_id);
	void SetConsoleId(u32 console_id);
	void SetTitleId(u64 title_id);
	void SetTitleVersion(u16 version);
	void SetLicenseType(ESLicenseType type);
	void SetEshopAccountId(u32 account_id);
	void SetAudit(u8 audit);
	int AddLimit(ESLimitCode id, u32 value);
	void SetContentMask(const std::vector<u16>& indexes);

private:
	static const int kSignatureIssuerLen = 0x40;
	static const int kEcdsaPublicKeyLen = 0x3C;
	static const int kFormatVersion = 1;
	static const int kCaCrlVersion = 0;
	static const int kSignerCrlVersion = 0;
	static const int kMaxLimitNum = 0x8;
	static const int kContentMaskBlockSize = 0x80;

	enum ESItemRight
	{
		ES_ITEM_RIGHT_PERMANENT = 1,
		ES_ITEM_RIGHT_SUBSCRIPTION = 2,
		ES_ITEM_RIGHT_CONTENT = 3,
		ES_ITEM_RIGHT_CONTENT_CONSUMPTION = 4,
		ES_ITEM_RIGHT_ACCESS_TITLE = 5,
		ES_ITEM_RIGHT_LIMITED_RESOURCE = 6,
	};

#pragma pack (push, 1)
	struct sTicketBody
	{
		char signature_issuer[kSignatureIssuerLen];
		u8 ecdsa_public_key[kEcdsaPublicKeyLen];
		u8 format_version;
		u8 ca_crl_version;
		u8 signer_crl_version;
		u8 title_key[Crypto::kAes128KeySize];
		u8 reserved0;
		u64 ticket_id;
		u32 console_id;
		u64 title_id;
		u8 reserved1[2];
		u16 title_version;
		u8 reserved2[8];
		u8 license_type;
		u8 common_key_index;
		u8 reserved3[0x2A];
		u32 eshop_account_id;
		u8 reserved4;
		u8 audit;
		u8 reserved5[0x42];
		struct sLimit
		{
			u32 id;
			u32 value;
		} limits[kMaxLimitNum];
	};

	struct sContentMaskHeader
	{
		u32 unk0;
		u32 total_size;
		u32 unk1;
		u32 unk2;
		u32 unk3;
		u32 header_size;
		u32 entry_num;
		u32 entry_size;
		u32 total_entry_size;
		u32 unk4;
	};

	struct sContentMaskChunk
	{
		u32 index_block;
		u8 num[kContentMaskBlockSize];
	};
#pragma pack (pop)

	struct sTicketBody body_;
	u32 limits_used_;

	std::vector<struct sContentMaskChunk> content_mask_;

	ByteBuffer ticket_;

	void ClearContentIndexControlEntry(struct sContentMaskChunk& entry);
};