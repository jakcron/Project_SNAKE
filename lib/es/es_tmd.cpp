#include "es_tmd.h"
#include "es_crypto.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

EsTmd::EsTmd() :
	content_(0)
{
	memset((u8*)&body_, 0, sizeof(struct sTitleMetadataBody));
}

EsTmd::~EsTmd()
{
}

int EsTmd::CreateTitleMetadata(const char* signature_issuer, const u8 rsa_modulus[Crypto::kRsa2048Size], const u8 rsa_priv_exponent[Crypto::kRsa2048Size])
{
	strncpy(body_.signature_issuer, signature_issuer, kSignatureIssuerLen);
	
	body_.format_version = kFormatVersion;
	body_.ca_crl_version = kCaCrlVersion;
	body_.signer_crl_version = kSignerCrlVersion;

	if (content_.size() == 0) die("[ERROR] No content was specified for Title Metadata!");

	safe_call(title_metadata_.alloc(EsCrypto::kRsa2048SignLen + sizeof(struct sTitleMetadataBody) + sizeof(struct sInfoRecord)*kInfoRecordNum + sizeof(struct sContentInfo)*content_.size()));

	// copy content info to buffer
	struct sContentInfo* content_info = (struct sContentInfo*)(title_metadata_.data() + EsCrypto::kRsa2048SignLen + sizeof(struct sTitleMetadataBody) + sizeof(struct sInfoRecord)*kInfoRecordNum);
	for (size_t i = 0; i < content_.size(); i++)
	{
		memcpy((u8*)&content_info[i], (const u8*)&content_[i], sizeof(struct sContentInfo));
	}

	// add info_record[0]
	struct sInfoRecord* info_record = (struct sInfoRecord*)(title_metadata_.data() + EsCrypto::kRsa2048SignLen + sizeof(struct sTitleMetadataBody));
	info_record[0].offset = 0;
	info_record[0].num = be_hword(content_.size());
	Crypto::Sha256((u8*)content_info, sizeof(struct sContentInfo)*content_.size(), info_record[0].hash);
	
	// finalise body_ data
	body_.content_count = be_hword(content_.size());
	Crypto::Sha256((u8*)info_record, sizeof(struct sInfoRecord)*kInfoRecordNum, body_.info_record_hash);

	// copy body_ to buffer
	memcpy(title_metadata_.data() + 0x140, (const u8*)&body_, sizeof(struct sTitleMetadataBody));

	// Sign header
	u8 hash[Crypto::kSha256HashLen];
	Crypto::Sha256(title_metadata_.data() + EsCrypto::kRsa2048SignLen, sizeof(struct sTitleMetadataBody), hash);
	if (EsCrypto::RsaSign(EsCrypto::ES_SIGN_RSA2048_SHA256, hash, rsa_modulus, rsa_priv_exponent, title_metadata_.data()) != 0)
	{
		fprintf(stderr, "[ERROR] Failed to sign TMD!\n");
		return 1;
	}

	return 0;
}

void EsTmd::SetSystemVersion(u64 system_version)
{
	body_.system_version = be_dword(system_version);
}

void EsTmd::SetTitleId(u64 title_id)
{
	body_.title_id = be_dword(title_id);
}

void EsTmd::SetTitleType(ESTitleType type)
{
	body_.title_type = be_word(type);
}

void EsTmd::SetGroupId(u16 group_id)
{
	body_.group_id = be_hword(group_id);
}

void EsTmd::SetCxiData(u32 save_size)
{
	body_.public_save_size = le_word(save_size);
}

void EsTmd::SetSrlData(u32 public_save_size, u32 private_save_size, u8 srl_flag)
{
	body_.public_save_size = le_word(public_save_size);
	body_.private_save_size = le_word(private_save_size);
	body_.srl_flag = srl_flag;
}

void EsTmd::SetAccessRights(u32 rights)
{
	body_.access_rights = be_word(rights);
}

void EsTmd::SetTitleVersion(u16 version)
{
	body_.title_version = be_hword(version);
}

void EsTmd::SetBootContentIndex(u16 num)
{
	body_.boot_content = be_word(num);
}

void EsTmd::AddContent(u32 id, u16 num, u16 flags, u64 size, const u8 hash[Crypto::kSha256HashLen])
{
	sContentInfo content_info;
	memset((u8*)&content_info, 0, sizeof(struct sContentInfo));

	size = align(size, kContentSizeAlign);

	content_info.id = be_word(id);
	content_info.num = be_hword(num);
	content_info.flags = be_hword(flags);
	content_info.size = be_dword(size);

	if ((flags & ES_CONTENT_TYPE_SHA1_HASH) == ES_CONTENT_TYPE_SHA1_HASH)
	{
		memset(content_info.hash, 0, Crypto::kSha256HashLen);
		memcpy(content_info.hash, hash, Crypto::kSha1HashLen);
	}
	else
	{
		memcpy(content_info.hash, hash, Crypto::kSha256HashLen);
	}

	content_.push_back(content_info);
}
