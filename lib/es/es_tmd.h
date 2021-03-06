#pragma once
#include <vector>
#include <fnd/types.h>
#include <fnd/memory_blob.h>
#include <es/es_crypto.h>
#include <es/es_cert.h>
#include <es/es_content_info.h>
#include <es/es_version.h>

class ESTmd
{
public:
	// public enums / constants
	enum ESTmdFormatVersion
	{
		ES_TMD_VER_0,
		ES_TMD_VER_1,
	};

	enum ESTitleType
	{
		ES_TITLE_TYPE_NC_TITLE = 0,
		ES_TITLE_TYPE_NG_TITLE = BIT(0),
		ES_TITLE_TYPE_RVL = BIT(1),
		ES_TITLE_TYPE_DATA = BIT(3),
		ES_TITLE_TYPE_CTR = BIT(6),
		ES_TITLE_TYPE_CAFE = BIT(8),
	};
	static const int kPlatformReservedDataSize = 0x3E;

	// Constructor/destructor
	ESTmd();
	~ESTmd();

	// Operator overloads
	void operator=(const ESTmd& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Tmd Serialisation
	void SerialiseTmd(const Crypto::sRsa2048Key& private_key);
	void SerialiseTmd(const Crypto::sRsa2048Key& private_key, ESTmdFormatVersion format);
	void SerialiseTmd(const Crypto::sRsa4096Key& private_key);
	void SerialiseTmd(const Crypto::sRsa4096Key& private_key, ESTmdFormatVersion format);
	void SetIssuer(const std::string& issuer);
	void SetCaCrlVersion(u8 version);
	void SetSignerCrlVersion(u8 version);
	void SetSystemVersion(u64 system_version);
	void SetTitleId(u64 title_id);
	void SetTitleType(ESTitleType type);
	void SetCompanyCode(const std::string& company_code);
	void SetPlatformReservedData(const u8* data, u32 size);
	void SetAccessRights(u32 access_rights);
	void SetTitleVersion(u16 title_version);
	void SetBootContentIndex(u16 index);
	void AddContent(const ESContentInfo& content_info);

	// Ticket Deserialisation
	void DeserialiseTmd(const u8* tmd_data, size_t size);
	bool ValidateSignature(const Crypto::sRsa2048Key& key) const;
	bool ValidateSignature(const Crypto::sRsa4096Key& key) const;
	bool ValidateSignature(const ESCert& signer) const;
	ESCrypto::ESSignType GetSignType() const;
	const u8* GetSignature() const;
	size_t GetSignatureSize() const;
	const std::string& GetIssuer() const;
	u8 GetFormatVersion() const;
	u8 GetCaCrlVersion() const;
	u8 GetSignerCrlVersion() const;
	u64 GetSystemVersion() const;
	u64 GetTitleId() const;
	ESTitleType GetTitleType() const;
	const std::string& GetCompanyCode() const;
	bool HasPlatformReservedData() const;
	const u8* GetPlatformReservedData() const;
	u32 GetAccessRights() const;
	u16 GetTitleVersion() const;
	u16 GetContentNum() const;
	u16 GetBootContentIndex() const;
	const std::vector<ESContentInfo>& GetContentList() const;

private:
	const std::string kModuleName = "ES_TMD";
	static const ESTmdFormatVersion kDefaultVersion = ESTmdFormatVersion::ES_TMD_VER_1;
	static const int kSignatureIssuerLen = 0x40;
	static const int kCompanyCodeLen = 2;
	static const u8 kFormatVersion = 1;
	static const u8 kCaCrlVersion = 0;
	static const u8 kSignerCrlVersion = 0;
	
	static const int kInfoRecordNum = 64;
	static const u32 kContentSizeAlign = 0x10;

	// Private Structures
#pragma pack (push, 1)
	// version 0
	struct sTitleMetadataBody_v0
	{
	private:
		char issuer_[kSignatureIssuerLen];
		u8 format_version_;
		u8 ca_crl_version_;
		u8 signer_crl_version_;
		u8 reserved0_;
		u64 system_version_;
		u64 title_id_;
		u32 title_type_;
		char company_code_[kCompanyCodeLen];
		u8 platform_reserved_data_[kPlatformReservedDataSize];
		u32 access_rights_;
		u16 title_version_;
		u16 content_num_;
		u16 boot_content_index_;
		u8 reserved3_[2];

	public:
		const char* issuer() const { return issuer_; }
		u8 format_version() const { return format_version_; }
		u8 ca_crl_version() const { return ca_crl_version_; }
		u8 signer_crl_version() const { return signer_crl_version_; }
		u64 system_version() const { return be_dword(system_version_); }
		u64 title_id() const { return be_dword(title_id_); }
		ESTitleType title_type() const { return (ESTitleType)be_word(title_type_); }
		const char* company_code() const { return company_code_; };
		const u8* platform_reserved_data() const { return platform_reserved_data_; }
		u32 access_rights() const { return be_word(access_rights_); }
		u16 title_version() const { return be_hword(title_version_); }
		u16 content_num() const { return be_hword(content_num_); }
		u16 boot_content_index() const { return be_hword(boot_content_index_); }

		void clear() { memset(this, 0, sizeof(sTitleMetadataBody_v0)); }

		void set_issuer(const char* issuer, int len) { memset(issuer_, 0, kSignatureIssuerLen); memcpy(issuer_, issuer, len < kSignatureIssuerLen ? len : kSignatureIssuerLen); }
		void set_format_version(u8 format_version) { format_version_ = format_version; }
		void set_ca_crl_version(u8 ca_crl_version) { ca_crl_version_ = ca_crl_version; }
		void set_signer_crl_version(u8 signer_crl_version) { signer_crl_version_ = signer_crl_version; }
		void set_system_version(u64 system_version) { system_version_ = be_dword(system_version); }
		void set_title_id(u64 title_id) { title_id_ = be_dword(title_id); }
		void set_title_type(ESTitleType title_type) { title_type_ = be_word(title_type); }
		void set_company_code(const char company_code[2]) { memcpy(company_code_, company_code, 2); };
		void set_platform_reserved_data(const u8 data[kPlatformReservedDataSize], u32 size) { memset(platform_reserved_data_, 0, kPlatformReservedDataSize); memcpy(platform_reserved_data_, data, size < kPlatformReservedDataSize ? size : kPlatformReservedDataSize); }
		void set_access_rights(u32 access_rights) { access_rights_ = be_word(access_rights); }
		void set_title_version(u16 title_version) { title_version_ = be_hword(title_version); }
		void set_content_num(u16 content_num) { content_num_ = be_hword(content_num); }
		void set_boot_content_index(u16 boot_content_index) { boot_content_index_ = be_hword(boot_content_index); }
	};

	struct sContentInfo_v0
	{
	private:
		u32 id_;
		u16 index_;
		u16 flag_;
		u64 size_;
		u8 hash_[Crypto::kSha1HashLen];
	public:
		u32 id() const { return be_word(id_); }
		u16 index() const { return be_hword(index_); }
		u16 flag() const { return be_hword(flag_); }
		u64 size() const { return be_dword(size_); }
		const u8* hash() const { return hash_; }

		void clear() { memset(this, 0, sizeof(sContentInfo_v0)); }

		void set_id(u32 id) { id_ = be_word(id); }
		void set_index(u16 index) { index_ = be_hword(index); }
		void set_flag(u16 flag) { flag_ = be_hword(flag); }
		void set_size(u64 size) { size_ = be_dword(size); }
		void set_hash(const u8 hash[Crypto::kSha1HashLen]) { memcpy(hash_, hash, Crypto::kSha1HashLen); }
	};

	
	// version 1
	struct sTitleMetadataBody_v1
	{
	private:
		char issuer_[kSignatureIssuerLen];
		u8 format_version_;
		u8 ca_crl_version_;
		u8 signer_crl_version_;
		u8 reserved0_;
		u64 system_version_;
		u64 title_id_;
		u32 title_type_;
		char company_code_[kCompanyCodeLen];
		u8 platform_reserved_data_[kPlatformReservedDataSize];
		u32 access_rights_;
		u16 title_version_;
		u16 content_num_;
		u16 boot_content_index_;
		u8 reserved3_[2];
		u8 info_records_hash_[Crypto::kSha256HashLen];

	public:
		const char* issuer() const { return issuer_; }
		u8 format_version() const { return format_version_; }
		u8 ca_crl_version() const { return ca_crl_version_; }
		u8 signer_crl_version() const { return signer_crl_version_; }
		u64 system_version() const { return be_dword(system_version_); }
		u64 title_id() const { return be_dword(title_id_); }
		ESTitleType title_type() const { return (ESTitleType)be_word(title_type_); }
		const char* company_code() const { return company_code_; };
		const u8* platform_reserved_data() const { return platform_reserved_data_; }
		u32 access_rights() const { return be_word(access_rights_); }
		u16 title_version() const { return be_hword(title_version_); }
		u16 content_num() const { return be_hword(content_num_); }
		u16 boot_content_index() const { return be_hword(boot_content_index_); }
		const u8* info_records_hash() const { return info_records_hash_; }

		void clear() { memset(this, 0, sizeof(sTitleMetadataBody_v1)); }

		void set_issuer(const char* issuer, int len) { memset(issuer_, 0, kSignatureIssuerLen); memcpy(issuer_, issuer, len < kSignatureIssuerLen ? len : kSignatureIssuerLen); }
		void set_format_version(u8 format_version) { format_version_ = format_version; }
		void set_ca_crl_version(u8 ca_crl_version) { ca_crl_version_ = ca_crl_version; }
		void set_signer_crl_version(u8 signer_crl_version) { signer_crl_version_ = signer_crl_version; }
		void set_system_version(u64 system_version) { system_version_ = be_dword(system_version); }
		void set_title_id(u64 title_id) { title_id_ = be_dword(title_id); }
		void set_title_type(ESTitleType title_type) { title_type_ = be_word(title_type); }
		void set_company_code(const char company_code[2]) { memcpy(company_code_, company_code, 2); };
		void set_platform_reserved_data(const u8 data[kPlatformReservedDataSize], u32 size) { memset(platform_reserved_data_, 0, kPlatformReservedDataSize); memcpy(platform_reserved_data_, data, size < kPlatformReservedDataSize ? size : kPlatformReservedDataSize); }
		void set_access_rights(u32 access_rights) { access_rights_ = be_word(access_rights); }
		void set_title_version(u16 title_version) { title_version_ = be_hword(title_version); }
		void set_content_num(u16 content_num) { content_num_ = be_hword(content_num); }
		void set_boot_content_index(u16 boot_content_index) { boot_content_index_ = be_hword(boot_content_index); }
		void set_info_records_hash(const u8* info_records_hash) { memcpy(info_records_hash_, info_records_hash, Crypto::kSha256HashLen); }
	};

	struct sInfoRecord
	{
	private:
		u16 offset_;
		u16 num_;
		u8 hash_[Crypto::kSha256HashLen];

	public:
		u16 offset() const { return be_hword(offset_); }
		u16 num() const { return be_hword(num_); }
		const u8* hash() const { return hash_; }

		void clear() { memset(this, 0, sizeof(sInfoRecord)); }

		void set_offset(u16 offset) { offset_ = be_hword(offset); }
		void set_num(u16 num) { num_ = be_hword(num); }
		void set_hash(const u8 hash[Crypto::kSha256HashLen]) { memcpy(hash_, hash, Crypto::kSha256HashLen); }
	};

	struct sContentInfo_v1
	{
	private:
		u32 id_;
		u16 index_;
		u16 flag_;
		u64 size_;
		u8 hash_[Crypto::kSha256HashLen];
	public:

		u32 id() const { return be_word(id_); }
		u16 index() const { return be_hword(index_); }
		u16 flag() const { return be_hword(flag_); }
		u64 size() const { return be_dword(size_); }
		const u8* hash() const { return hash_; }

		void clear() { memset(this, 0, sizeof(sContentInfo_v1)); }

		void set_id(u32 id) { id_ = be_word(id); }
		void set_index(u16 index) { index_ = be_hword(index); }
		void set_flag(u16 flag) { flag_ = be_hword(flag); }
		void set_size(u64 size) { size_ = be_dword(size); }
		// these try to ensure correct hashtype flag when used
		void set_sha1_hash(const u8 hash[Crypto::kSha1HashLen]) { memset(hash_, 0, Crypto::kSha256HashLen); memcpy(hash_, hash, Crypto::kSha1HashLen); }
		void set_sha256_hash(const u8 hash[Crypto::kSha256HashLen]) { memcpy(hash_, hash, Crypto::kSha256HashLen); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// members for deserialised data
	std::string issuer_;
	u8 format_version_;
	u8 ca_crl_version_;
	u8 signer_crl_version_;
	u64 system_version_;
	u64 title_id_;
	ESTitleType title_type_;
	std::string company_code_;
	u8 platform_reserved_data_[kPlatformReservedDataSize];
	u32 access_rights_;
	u16 title_version_;
	u16 content_num_;
	u16 boot_content_index_;
	std::vector<ESContentInfo> content_list_;

	// (De)serialiser
	void HashSerialisedData(ESCrypto::ESSignType sign_type, u8* hash) const;
	void SerialiseWithoutSign_v0(ESCrypto::ESSignType sign_type);
	void SerialiseWithoutSign_v1(ESCrypto::ESSignType sign_type);
	u8 GetRawBinaryFormatVersion(const u8* raw_tmd_body);
	void Deserialise_v0(const u8* tmd_data, size_t size);
	void Deserialise_v1(const u8* tmd_data, size_t size);


	bool IsSupportedFormatVersion(u8 version) const;

	void ClearDeserialisedVariables();
};

