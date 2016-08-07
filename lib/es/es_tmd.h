#pragma once
#include <vector>
#include "types.h"
#include "ByteBuffer.h"
#include "crypto.h"

class EsTmd
{
public:
	enum ESContentType
	{
		ES_CONTENT_TYPE_ENCRYPTED = BIT(0),
		ES_CONTENT_TYPE_DISC = BIT(1),
		ES_CONTENT_TYPE_HASHED = BIT(1),
		ES_CONTENT_TYPE_CFM = BIT(3),
		ES_CONTENT_TYPE_SHA1_HASH = BIT(13),
		ES_CONTENT_TYPE_OPTIONAL = BIT(14),
		ES_CONTENT_TYPE_SHARED = BIT(15),
	};

	enum ESTitleType
	{
		ES_TITLE_TYPE_DATA = BIT(3),
		ES_TITLE_TYPE_CTR = BIT(6)
	};

	EsTmd();
	~EsTmd();

	int CreateTitleMetadata(const char* signature_issuer, const u8 rsa_modulus[Crypto::kRsa2048Size], const u8 rsa_priv_exponent[Crypto::kRsa2048Size]);

	inline const u8* data_blob() const { return title_metadata_.data_const(); }
	inline u32 data_size() const { return title_metadata_.size(); }

	void SetSystemVersion(u64 system_version);
	void SetTitleId(u64 title_id);
	void SetTitleType(ESTitleType type);
	void SetGroupId(u16 group_id);
	void SetCxiData(u32 save_size);
	void SetSrlData(u32 public_save_size, u32 private_save_size, u8 srl_flag);
	void SetAccessRights(u32 rights);
	void SetTitleVersion(u16 version);
	void SetBootContentIndex(u16 num);
	void AddContent(u32 id, u16 num, u16 flags, u64 size, const u8 hash[Crypto::kSha256HashLen]);

private:
	static const int kSignatureIssuerLen = 0x40;
	static const u8 kFormatVersion = 1;
	static const u8 kCaCrlVersion = 0;
	static const u8 kSignerCrlVersion = 0;
	static const int kInfoRecordNum = 64;
	static const u32 kContentSizeAlign = 0x10;

#pragma pack (push, 1)
	struct sInfoRecord
	{
		u16 offset;
		u16 num;
		u8 hash[Crypto::kSha256HashLen];
	};

	struct sTitleMetadataBody
	{
		char signature_issuer[kSignatureIssuerLen];
		u8 format_version;
		u8 ca_crl_version;
		u8 signer_crl_version;
		u8 reserved0;
		u64 system_version;
		u64 title_id;
		u32 title_type;
		u16 group_id;
		u32 public_save_size;
		u32 private_save_size;
		u8 reserved1[4];
		u8 srl_flag; // SRL = ds(i) rom
		u8 reserved2[0x31];
		u32 access_rights;
		u16 title_version;
		u16 content_count;
		u16 boot_content;
		u8 reserved3[2];
		u8 info_record_hash[Crypto::kSha256HashLen];
	};

	struct sContentInfo
	{
		u32 id;
		u16 num;
		u16 flags;
		u64 size;
		u8 hash[Crypto::kSha256HashLen];
	};
#pragma pack (pop)

	struct sTitleMetadataBody body_;
	std::vector<struct sContentInfo> content_;

	ByteBuffer title_metadata_;

};