#pragma once
#include <vector>
#include "types.h"
#include "ByteBuffer.h"
#include "crypto.h"

#include "es_cert.h"

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

#pragma pack (push, 1)
	struct sContentInfo
	{
		u32 id;
		u16 index;
		u16 flags;
		u64 size;
		u8 hash[Crypto::kSha256HashLen];
	};
#pragma pack (pop)

	EsTmd();
	~EsTmd();

	void operator=(const EsTmd& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Tmd Serialisation
	void SerialiseTmd(const Crypto::sRsa2048Key& private_key);
	void SerialiseTmd(const Crypto::sRsa2048Key& private_key, bool use_sha1);
	void SerialiseTmd(const Crypto::sRsa4096Key& private_key);
	void SerialiseTmd(const Crypto::sRsa4096Key& private_key, bool use_sha1);
	void SetIssuer(const std::string& issuer);
	void SetFormatVersion(u8 version);
	void SetCaCrlVersion(u8 version);
	void SetSignerCrlVersion(u8 version);
	void SetSystemVersion(u64 system_version);
	void SetTitleId(u64 title_id);
	void SetTitleType(ESTitleType type);
	void SetGroupId(u16 group_id);
	void SetCtrSaveSize(u32 size);
	void SetTwlSaveSize(u32 public_size, u32 private_size);
	void SetTwlFlag(u8 flag);
	void SetAccessRights(u32 access_rights);
	void SetTitleVersion(u16 title_version);
	void SetBootContentIndex(u16 index);
	void AddContent(u32 id, u16 index, u16 flags, u64 size, u8 hash[Crypto::kSha256HashLen]);

	// Ticket Deserialisation
	void DeserialiseTmd(const u8* tmd_data);
	bool ValidateSignature(const Crypto::sRsa2048Key& key) const;
	bool ValidateSignature(const Crypto::sRsa4096Key& key) const;
	bool ValidateSignature(const EsCert& signer) const;
	const std::string& GetIssuer() const;
	u8 GetFormatVersion() const;
	u8 GetCaCrlVersion() const;
	u8 GetSignerCrlVersion() const;
	u64 GetSystemVersion() const;
	u64 GetTitleId() const;
	ESTitleType GetTitleType() const;
	u16 GetGroupId() const;
	u32 GetCtrSaveDataSize() const;
	u32 GetTwlPublicSaveDataSize() const;
	u32 GetTwlPrivateSaveDataSize() const;
	u8 GetTwlFlag() const;
	u32 GetAccessRights() const;
	u16 GetTitleVersion() const;
	u16 GetContentNum() const;
	u16 GetBootContentIndex() const;
	const std::vector<sContentInfo>& GetContentList() const;


	// Flag utils
	static bool IsEncrypted(u16 flag);
	static bool IsOptional(u16 flag);
	static bool IsSha1Hash(u16 flag);
private:
	const std::string kModuleName = "ES_TMD";
	static const int kSignatureIssuerLen = 0x40;
	static const u8 kFormatVersion = 1;
	static const u8 kCaCrlVersion = 0;
	static const u8 kSignerCrlVersion = 0;
	static const int kInfoRecordNum = 64;
	static const u32 kContentSizeAlign = 0x10;

	// Private Structures
#pragma pack (push, 1)
	struct sInfoRecord
	{
		u16 offset;
		u16 num;
		u8 hash[Crypto::kSha256HashLen];
	};

	struct sTitleMetadataBodyVersion1
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
		struct sPlatormDependentRegion
		{
			u32 public_save_size;
			u32 private_save_size;
			u8 reserved1[4];
			u8 twl_flag;
			u8 reserved2[0x31];
		} platform_dependent;
		u32 access_rights;
		u16 title_version;
		u16 content_num;
		u16 boot_content_index;
		u8 reserved3[2];
		u8 info_records_hash[Crypto::kSha256HashLen];
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// serialised data staging ground
	sTitleMetadataBodyVersion1 tmd_body_;


	// serialised data get interface
	inline const char* signature_issuer() const { return tmd_body_.signature_issuer; }
	inline u8 format_version() const { return tmd_body_.format_version; }
	inline u8 ca_crl_version() const { return tmd_body_.ca_crl_version; }
	inline u8 signer_crl_version() const { return tmd_body_.signer_crl_version; }
	inline u64 system_version() const { return be_dword(tmd_body_.system_version); }
	inline u64 title_id() const { return be_dword(tmd_body_.title_id); }
	inline ESTitleType title_type() const { return (ESTitleType)be_word(tmd_body_.title_type); }
	inline u16 group_id() const { return be_hword(tmd_body_.group_id); };
	inline u32 public_save_data_size() const { return le_word(tmd_body_.platform_dependent.public_save_size); }
	inline u32 private_save_data_size() const { return le_word(tmd_body_.platform_dependent.private_save_size); }
	inline u8 twl_flag() const { return tmd_body_.platform_dependent.twl_flag; }
	inline u32 access_rights() const { return be_word(tmd_body_.access_rights); }
	inline u16 title_version() const { return be_hword(tmd_body_.title_version); }
	inline u16 content_num() const { return be_hword(tmd_body_.content_num); }
	inline u16 boot_content_index() const { return be_hword(tmd_body_.boot_content_index); }
	inline const u8* info_records_hash() const { return tmd_body_.info_records_hash; }

	inline u16 get_info_record_offset(const sInfoRecord& record) const { return be_hword(record.offset); }
	inline u16 get_info_record_num(const sInfoRecord& record) const { return be_hword(record.num); }
	inline const u8* get_info_record_hash(const sInfoRecord& record) const { return record.hash; }

	inline u32 get_content_info_id(const sContentInfo& info) const { return be_word(info.id); };
	inline u16 get_content_info_index(const sContentInfo& info) const { return be_hword(info.index); }
	inline u16 get_content_info_flags(const sContentInfo& info) const { return be_hword(info.flags); }
	inline u64 get_content_info_size(const sContentInfo& info) const { return be_dword(info.size); }
	inline const u8* get_content_info_hash(const sContentInfo& info) const { return info.hash; }

	// serialised data set interface
	inline void set_signature_issuer(const char* issuer, int len) { memset(tmd_body_.signature_issuer, 0, kSignatureIssuerLen); memcpy(tmd_body_.signature_issuer, issuer, len < kSignatureIssuerLen ? len : kSignatureIssuerLen); }
	inline void set_format_version(u8 format_version) { tmd_body_.format_version = format_version; }
	inline void set_ca_crl_version(u8 ca_crl_version) { tmd_body_.ca_crl_version = ca_crl_version; }
	inline void set_signer_crl_version(u8 signer_crl_version) { tmd_body_.signer_crl_version = signer_crl_version; }
	inline void set_system_version(u64 system_version) { tmd_body_.system_version = be_dword(system_version); }
	inline void set_title_id(u64 title_id) { tmd_body_.title_id = be_dword(title_id); }
	inline void set_title_type(ESTitleType title_type) { tmd_body_.title_type = be_word(title_type); }
	inline void set_group_id(u16 group_id) { tmd_body_.group_id = be_hword(group_id); };
	inline void set_public_save_data_size(u32 public_save_data_size) { tmd_body_.platform_dependent.public_save_size = le_word(public_save_data_size); }
	inline void set_private_save_data_size(u32 private_save_data_size) { tmd_body_.platform_dependent.private_save_size = le_word(private_save_data_size); }
	inline void set_twl_flag(u8 twl_flag) { tmd_body_.platform_dependent.twl_flag = twl_flag; }
	inline void set_access_rights(u32 access_rights) { tmd_body_.access_rights = be_word(access_rights); }
	inline void set_title_version(u16 title_version) { tmd_body_.title_version = be_hword(title_version); }
	inline void set_content_num(u16 content_num) { tmd_body_.content_num = be_hword(content_num); }
	inline void set_boot_content_index(u16 boot_content_index) { tmd_body_.boot_content_index = be_hword(boot_content_index); }
	inline void set_info_records_hash(const u8* info_records_hash) { memcpy(tmd_body_.info_records_hash, info_records_hash, Crypto::kSha256HashLen); }

	inline void set_info_record_offset(sInfoRecord& record, u16 offset) { record.offset = be_hword(offset); }
	inline void set_info_record_num(sInfoRecord& record, u16 num) { record.num = be_hword(num); }
	inline void set_info_record_hash(sInfoRecord& record, const u8 hash[Crypto::kSha256HashLen]) { memcpy(record.hash, hash, Crypto::kSha256HashLen); }

	inline void set_content_info_id(sContentInfo& info, u32 id) { info.id = be_word(id); };
	inline void set_content_info_index(sContentInfo& info, u16 index) { info.index = be_hword(index); }
	inline void set_content_info_flags(sContentInfo& info, u16 flags) { info.flags = be_hword(flags); }
	inline void set_content_info_size(sContentInfo& info, u64 size) { info.size = be_dword(size); }
	inline void set_content_info_hash(sContentInfo& info, const u8 hash[Crypto::kSha256HashLen], bool is_sha1) { memset(info.hash, 0, Crypto::kSha256HashLen); memcpy(info.hash, hash, is_sha1? Crypto::kSha1HashLen : Crypto::kSha256HashLen); }

	// members for deserialised data
	std::string issuer_;
	u8 format_version_;
	u8 ca_crl_version_;
	u8 signer_crl_version_;
	u64 system_version_;
	u64 title_id_;
	ESTitleType title_type_;
	u16 group_id_;
	u32 public_save_data_size_;
	u32 private_save_data_size_;
	u8 twl_flag_;
	u32 access_rights_;
	u16 title_version_;
	u16 content_num_;
	u16 boot_content_index_;
	std::vector<sContentInfo> content_list_;

	// (De)serialiser
	void HashSerialisedData(EsCrypto::EsSignType sign_type, u8* hash) const;
	void SerialiseWithoutSign(EsCrypto::EsSignType sign_type);

	bool IsSupportedFormatVersion(u8 version) const;

	void ClearDeserialisedVariables();
};

