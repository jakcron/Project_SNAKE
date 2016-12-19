#pragma once
#include <vector>
#include <fnd/types.h>
#include <fnd/ByteBuffer.h>
#include <es/es_crypto.h>
#include <es/es_cert.h>

class ESTicket
{
public:
	// Public Enums
	enum ESTicketFormatVersion
	{
		ES_TIK_VER_0,
		ES_TIK_VER_1,
	};
	
	enum ESLicenseType
	{
		ES_LICENSE_PERMANENT = 0,
		ES_LICENSE_DEMO = 1,
		ES_LICENSE_TRIAL = 2,
		ES_LICENSE_RENTAL = 3,
		ES_LICENSE_SUBSCRIPTION = 4,
		ES_LICENSE_SERVICE = 5,
	};

	enum ESLimitCode
	{
		ES_LC_DURATION_TIME = 1,
		ES_LC_ABSOLUTE_TIME = 2,
		ES_LC_NUM_TITLES = 3,
		ES_LC_NUM_LAUNCH = 4,
		ES_LC_ELAPSED_TIME = 5,
	};

	enum ESItemRight
	{
		ES_ITEM_RIGHT_PERMANENT = 1,
		ES_ITEM_RIGHT_SUBSCRIPTION = 2,
		ES_ITEM_RIGHT_CONTENT = 3,
		ES_ITEM_RIGHT_CONTENT_CONSUMPTION = 4,
		ES_ITEM_RIGHT_ACCESS_TITLE = 5,
		ES_ITEM_RIGHT_LIMITED_RESOURCE = 6,
	};

	// Constructor/Destructor
	ESTicket();
	~ESTicket();

	void operator=(const ESTicket& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Ticket Serialisation
	void SerialiseTicket(const Crypto::sRsa2048Key& private_key);
	void SerialiseTicket(const Crypto::sRsa2048Key& private_key, ESTicketFormatVersion format);
	void SerialiseTicket(const Crypto::sRsa4096Key& private_key);
	void SerialiseTicket(const Crypto::sRsa4096Key& private_key, ESTicketFormatVersion format);
	void SetIssuer(const std::string& issuer);
	void SetServerPublicKey(const Crypto::sEccPoint& public_key);
	void SetCaCrlVersion(u8 version);
	void SetSignerCrlVersion(u8 version);
	void SetEncryptedTitleKey(const u8 enc_title_key[Crypto::kAes128KeySize]);
	void SetTitleKey(const u8 title_key[Crypto::kAes128KeySize], const u8 common_key[Crypto::kAes128KeySize]);
	void SetTicketId(u64 ticket_id);
	void SetDeviceId(u32 device_id);
	void SetTitleId(u64 title_id);
	void SetSystemAccessMask(u16 system_access_mask);
	void SetTitleVersion(u16 title_version);
	void SetAccessTitleId(u32 access_title_id);
	void SetAccessTitleIdMask(u32 access_title_id_mask);
	void SetLicenseType(ESLicenseType license_type);
	void SetCommonKeyIndex(u8 index);
	void SetEShopAccountId(u32 account_id);
	void SetAudit(u8 audit);
	void AddLimit(ESLimitCode limit_code, u32 value);
	void RemoveLimit(ESLimitCode limit_code);
	void EnableContent(u16 index);

	// Ticket Deserialisation
	void DeserialiseTicket(const u8* ticket_data);
	bool ValidateSignature(const Crypto::sRsa2048Key& key) const;
	bool ValidateSignature(const Crypto::sRsa4096Key& key) const;
	bool ValidateSignature(const ESCert& signer) const;
	const std::string& GetIssuer() const;
	const Crypto::sEccPoint& GetServerPublicKey() const;
	u8 GetFormatVersion() const;
	u8 GetCaCrlVersion() const;
	u8 GetSignerCrlVersion() const;
	const u8* GetEncryptedTitleKey() const;
	const u8* GetTitleKey(const u8* common_key);
	void GetTitleKey(const u8 common_key[Crypto::kAes128KeySize], u8 title_key[Crypto::kAes128KeySize]) const;
	u64 GetTicketId() const;
	bool IsTicketAssociatedWithDevice() const;
	u32 GetDeviceId() const;
	u64 GetTitleId() const;
	u16 GetSystemAccessMask() const;
	u16 GetTitleVersion() const;
	u32 GetAccessTitleId() const;
	u32 GetAccessTitleIdMask() const;
	ESLicenseType GetLicenseType() const;
	u8 GetCommonKeyIndex() const;
	bool IsTicketAssociatedWithEShopAccount() const;
	u32 GetEShopAccountId() const;
	u8 GetAudit() const;
	bool IsLimitSet(ESLimitCode limit_code) const;
	u32 GetLimit(ESLimitCode limit_code) const;
	bool IsContentEnabled(u16 content_index) const;
	const std::vector<u16>& GetEnabledContentList() const;


private:
	const std::string kModuleName = "ES_TICKET";

	static const int kSignatureIssuerLen = 0x40;
	static const int kEcdsaPublicKeyLen = 0x3C;
	static const int kFormatVersion = 1;
	static const int kCaCrlVersion = 0;
	static const int kSignerCrlVersion = 0;
	static const u32 kEnabledIndexMax_v0 = 0x200; // 0x0-0x1ff
	static const u32 kEnabledIndexMax_v1 = 0x10000; // 0x0-0xffff
	static const int kContentIndexBlockSize = 0x80;
	static const u16 kContentIndexUpperMask = 0xFC00;
	static const u16 kContentIndexLowerMask = 0x3FF;

	// Private Enums
	enum ESLicenseTypePrivate
	{
		ES_LICENSE_MASK = 15,
	};

	enum ESLimitCodePrivate
	{
		ES_MAX_LIMIT_TYPE = 8,
	};

	// Private Structures
#pragma pack (push, 1)
	struct sLimit
	{
		u32 id;
		u32 value;
	};

	struct sTicketBody_v0
	{
	private:
		char issuer_[kSignatureIssuerLen];
		Crypto::sEccPoint server_public_key_;
		u8 format_version_;
		u8 ca_crl_version_;
		u8 signer_crl_version_;
		u8 encrypted_title_key_[Crypto::kAes128KeySize];
		u8 reserved0_;
		u64 ticket_id_;
		u32 device_id_;
		u64 title_id_;
		u16 system_title_access_mask_;
		u16 title_version_;
		u32 access_title_id_;
		u32 access_title_id_mask_;
		u8 license_type_;
		u8 key_id_;
		u8 reserved3_[0x2f];
		u8 audit_; // VC title related (RVL only?)
		u8 enabled_content_bits_[0x40];
		u8 reserved5_[0x2];
		sLimit limits_[ES_MAX_LIMIT_TYPE];

	public:
		const char* issuer() const { return issuer_; }
		const Crypto::sEccPoint* server_public_key() const { return &server_public_key_; }
		u8 format_version() const { return format_version_; }
		u8 ca_crl_version() const { return ca_crl_version_; }
		u8 signer_crl_version() const { return signer_crl_version_; }
		const u8* encrypted_title_key() const { return encrypted_title_key_; }
		u64 ticket_id() const { return be_dword(ticket_id_); }
		u32 device_id() const { return be_word(device_id_); }
		u64 title_id() const { return be_dword(title_id_); }
		u16 system_title_access_mask() const { return be_hword(system_title_access_mask_); }
		u16 title_version() const { return be_hword(title_version_); }
		u32 access_title_id() const { return be_word(access_title_id_); }
		u32 access_title_id_mask() const { return be_word(access_title_id_mask_); }
		ESLicenseType license_type() const { return (ESLicenseType)(license_type_ & ES_LICENSE_MASK); }
		u8 key_id() const { return key_id_; }
		u8 audit() const { return audit_; }
		bool is_content_enabled(u16 index) const { return (enabled_content_bits_[((index / 8) & 0x3f)] & BIT(index % 8)) != 0; }
		ESLimitCode limit_code(u8 index) const { return (ESLimitCode)be_word(limits_[index].id); }
		u32 limit_value(u8 index) const { return be_word(limits_[index].value); }

		void clear() { memset(this, 0, sizeof(sTicketBody_v0)); }
		void set_issuer(const char* issuer, int len) { memset(issuer_, 0, kSignatureIssuerLen); memcpy(issuer_, issuer, len < kSignatureIssuerLen ? len : kSignatureIssuerLen); }
		void set_server_public_key(const Crypto::sEccPoint* public_key) { server_public_key_ = *public_key; }
		void set_format_version(u8 format_version) { format_version_ = format_version; }
		void set_ca_crl_version(u8 ca_crl_version) { ca_crl_version_ = ca_crl_version; }
		void set_signer_crl_version(u8 signer_crl_version) { signer_crl_version_ = signer_crl_version; }
		void set_encrypted_title_key(const u8 enc_key[Crypto::kAes128KeySize]) { memcpy(encrypted_title_key_, enc_key, Crypto::kAes128KeySize); }
		void set_ticket_id(u64 ticket_id) { ticket_id_ = be_dword(ticket_id); }
		void set_device_id(u32 device_id) { device_id_ = be_word(device_id); }
		void set_title_id(u64 title_id) { title_id_ = be_dword(title_id); }
		void set_system_title_access_mask(u16 system_title_access_mask) { system_title_access_mask_ = be_hword(system_title_access_mask); }
		void set_title_version(u16 title_version) { title_version_ = be_hword(title_version); }
		void set_access_title_id(u32 access_title_id) { access_title_id_ = be_word(access_title_id); }
		void set_access_title_id_mask(u32 access_title_id_mask) { access_title_id_mask_ = be_word(access_title_id_mask); }
		void set_license_type(ESLicenseType license_type) { license_type_ = license_type & ES_LICENSE_MASK; }
		void set_key_id(u8 key_id) { key_id_ = key_id; }
		void set_audit(u8 audit) { audit_ = audit; }
		void enable_content_index(u16 index) { enabled_content_bits_[(index / 8) % 0x40] |= BIT(index % 8); }
		void disable_content_index(u16 index) { enabled_content_bits_[(index / 8) % 0x40] &= ~BIT(index % 8); }
		void set_limit(u8 index, ESLimitCode code, u32 value) { limits_[index].id = be_word(code); limits_[index].value = be_word(value); }
	};

	struct sTicketBody_v1
	{
	private:
		char issuer_[kSignatureIssuerLen];
		Crypto::sEccPoint server_public_key_;
		u8 format_version_;
		u8 ca_crl_version_;
		u8 signer_crl_version_;
		u8 encrypted_title_key_[Crypto::kAes128KeySize];
		u8 reserved0_;
		u64 ticket_id_;
		u32 device_id_;
		u64 title_id_;
		u8 reserved1_[2];
		u16 title_version_;
		u8 reserved2_[8];
		u8 license_type_;
		u8 key_id_;
		u8 reserved3_[0x2A];
		u32 eshop_account_id_;
		u8 reserved5_[0x44];
		sLimit limits_[ES_MAX_LIMIT_TYPE];
	public:
		const char* issuer() const { return issuer_; }
		const Crypto::sEccPoint* server_public_key() const { return &server_public_key_; }
		u8 format_version() const { return format_version_; }
		u8 ca_crl_version() const { return ca_crl_version_; }
		u8 signer_crl_version() const { return signer_crl_version_; }
		const u8* encrypted_title_key() const { return encrypted_title_key_; }
		u64 ticket_id() const { return be_dword(ticket_id_); }
		u32 device_id() const { return be_word(device_id_); }
		u64 title_id() const { return be_dword(title_id_); }
		u16 title_version() const { return be_hword(title_version_); }
		ESLicenseType license_type() const { return (ESLicenseType)(license_type_ & ES_LICENSE_MASK); }
		u8 key_id() const { return key_id_; }
		u32 eshop_account_id() const { return be_word(eshop_account_id_); }
		ESLimitCode limit_code(u8 index) const { return (ESLimitCode)be_word(limits_[index].id); }
		u32 limit_value(u8 index) const { return be_word(limits_[index].value); }

		void clear() { memset(this, 0, sizeof(sTicketBody_v1)); }
		void set_issuer(const char* issuer, int len) { memset(issuer_, 0, kSignatureIssuerLen); memcpy(issuer_, issuer, len < kSignatureIssuerLen ? len : kSignatureIssuerLen); }
		void set_server_public_key(const Crypto::sEccPoint* public_key) { server_public_key_ = *public_key; }
		void set_format_version(u8 format_version) { format_version_ = format_version; }
		void set_ca_crl_version(u8 ca_crl_version) { ca_crl_version_ = ca_crl_version; }
		void set_signer_crl_version(u8 signer_crl_version) { signer_crl_version_ = signer_crl_version; }
		void set_encrypted_title_key(const u8 enc_key[Crypto::kAes128KeySize]) { memcpy(encrypted_title_key_, enc_key, Crypto::kAes128KeySize); }
		void set_ticket_id(u64 ticket_id) { ticket_id_ = be_dword(ticket_id); }
		void set_device_id(u32 device_id) { device_id_ = be_word(device_id); }
		void set_title_id(u64 title_id) { title_id_ = be_dword(title_id); }
		void set_title_version(u16 title_version) { title_version_ = be_hword(title_version); }
		void set_license_type(ESLicenseType license_type) { license_type_ = license_type & ES_LICENSE_MASK; }
		void set_key_id(u8 key_id) { key_id_ = key_id; }
		void set_eshop_account_id(u32 account_id) { eshop_account_id_ = be_word(account_id); }
		void set_limit(u8 index, ESLimitCode code, u32 value) { limits_[index].id = be_word(code); limits_[index].value = be_word(value); }
	};

	struct sContentIndexChunkHeader
	{
	private:
		u32 unk0_;
		u32 total_size_;
		u32 unk1_;
		u32 unk2_;
		u32 unk3_;
		u32 header_size_;
		u32 chunk_num_;
		u32 chunk_size_;
		u32 total_chunks_size_;
		u32 unk4_;
	public:
		static const u32 kUnk0Default = 0x00010014;
		static const u32 kUnk1Default = 0x00000014;
		static const u32 kUnk2Default = 0x00010014;
		static const u32 kUnk3Default = 0x00000000;
		static const u32 kUnk4Default = 0x00030000;

		u32 unk0() const { return be_word(unk0_); }
		u32 total_size() const { return be_word(total_size_); }
		u32 unk1() const { return be_word(unk1_); }
		u32 unk2() const { return be_word(unk2_); }
		u32 unk3() const { return be_word(unk3_); }
		u32 header_size() const { return be_word(header_size_); }
		u32 chunk_num() const { return be_word(chunk_num_); }
		u32 chunk_size() const { return be_word(chunk_size_); }
		u32 total_chunks_size() const { return be_word(total_chunks_size_); }
		u32 unk4() const { return be_word(unk4_); }

		void clear() { memset(this, 0, sizeof(sContentIndexChunkHeader)); }

		void set_unk0(u32 unk0) { unk0_ = be_word(unk0); }
		void set_total_size(u32 total_size) { total_size_ = be_word(total_size); }
		void set_unk1(u32 unk1) { unk1_ = be_word(unk1); }
		void set_unk2(u32 unk2) { unk2_ = be_word(unk2); }
		void set_unk3(u32 unk3) { unk3_ = be_word(unk3); }
		void set_header_size(u32 header_size) { header_size_ = be_word(header_size); }
		void set_chunk_num(u32 chunk_num) { chunk_num_ = be_word(chunk_num); }
		void set_chunk_size(u32 chunk_size) { chunk_size_ = be_word(chunk_size); }
		void set_total_chunks_size(u32 total_chunks_size) { total_chunks_size_ = be_word(total_chunks_size); }
		void set_unk4(u32 unk4) { unk4_ = be_word(unk4); }
	};

	struct sContentIndexChunk
	{
	private:
		u32 index_high_bits;
		u8 index_bits[kContentIndexBlockSize];
	public:
		u32 index_group() const { return be_word(index_high_bits); }
		bool is_index_enabled(u16 index) const { return (index_group() == get_index_high_bits(index)) && ((index_bits[get_index_low_bits(index) / 8] & BIT(get_index_low_bits(index) % 8)) != 0); }

		void clear() { memset(this, 0, sizeof(sContentIndexChunk)); }

		void set_index_group(u16 index) { index_high_bits = be_hword(get_index_high_bits(index)); }
		void enable_index(u16 index) { index_bits[get_index_low_bits(index) / 8] |= BIT(get_index_low_bits(index) % 8); }
		void disable_index(u16 index) { index_bits[get_index_low_bits(index) / 8] &= ~BIT(get_index_low_bits(index) % 8); }

		inline u16 get_index_low_bits(u16 index) const { return index & kContentIndexLowerMask; }
		inline u16 get_index_high_bits(u16 index) const { return index & kContentIndexUpperMask; }
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// members for deserialised data
	struct sEsLimit
	{
		ESLimitCode limit_code;
		u32 value;
	};

	std::string issuer_;
	Crypto::sEccPoint server_public_key_;
	u8 format_version_;
	u8 ca_crl_version_;
	u8 signer_crl_version_;
	u8 enc_title_key_[Crypto::kAes128KeySize];
	u8 dec_title_key_[Crypto::kAes128KeySize];
	u64 ticket_id_;
	u32 device_id_;
	u64 title_id_;
	u16 system_title_access_mask_;
	u16 title_version_;
	u32 access_title_id_;
	u32 access_title_id_mask_;
	ESLicenseType license_type_;
	ESItemRight item_right_;
	u8 common_key_index_;
	u32 eshop_account_id_;
	u8 audit_;
	std::vector<sEsLimit> limits_;
	std::vector<u16> enabled_content_;

	bool is_common_key_set_;
	u8 common_key_[Crypto::kAes128KeySize];

	// Internal processing member methods
	void CreateTitleKeyIv(u64 title_id, u8 iv[Crypto::kAesBlockSize]) const;
	void EncryptTitleKey(const u8 title_key[Crypto::kAes128KeySize], u64 title_id, const u8 common_key[Crypto::kAes128KeySize], u8 enc_title_key[Crypto::kAes128KeySize]) const;
	void DecryptTitleKey(const u8 enc_title_key[Crypto::kAes128KeySize], u64 title_id, const u8 common_key[Crypto::kAes128KeySize], u8 title_key[Crypto::kAes128KeySize]) const;

	// (De)serialiser
	void HashSerialisedData(ESCrypto::ESSignType sign_type, u8* hash) const;
	void SerialiseWithoutSign_v0(ESCrypto::ESSignType sign_type);
	void SerialiseWithoutSign_v1(ESCrypto::ESSignType sign_type);
	u8 GetRawBinaryFormatVersion(const u8* raw_tik_body);
	void Deserialise_v0(const u8* tik_data);
	void Deserialise_v1(const u8* tik_data);

	bool IsSupportedFormatVersion(u8 version) const;

	void ClearDeserialisedVariables();
};

