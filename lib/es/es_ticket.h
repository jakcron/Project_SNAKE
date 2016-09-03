#pragma once
#include <vector>
#include "types.h"
#include "ByteBuffer.h"
#include "crypto.h"

#include "es_cert.h"

class EsTicket
{
public:
	// Public Enums
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
	EsTicket();
	~EsTicket();

	void operator=(const EsTicket& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Ticket Serialisation
	void SerialiseTicket(const Crypto::sRsa2048Key& private_key);
	void SerialiseTicket(const Crypto::sRsa2048Key& private_key, bool use_sha1);
	void SerialiseTicket(const Crypto::sRsa4096Key& private_key);
	void SerialiseTicket(const Crypto::sRsa4096Key& private_key, bool use_sha1);
	void SetIssuer(const std::string& issuer);
	void SetFormatVersion(u8 version);
	void SetCaCrlVersion(u8 version);
	void SetSignerCrlVersion(u8 version);
	void SetEncryptedTitleKey(const u8 enc_title_key[Crypto::kAes128KeySize]);
	void SetTitleKey(const u8 title_key[Crypto::kAes128KeySize], const u8 common_key[Crypto::kAes128KeySize]);
	void SetTicketId(u64 ticket_id);
	void SetDeviceId(u32 device_id);
	void SetTitleId(u64 title_id);
	void SetTitleVersion(u16 title_version);
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
	bool ValidateSignature(const EsCert& signer) const;
	const std::string& GetIssuer() const;
	u8 GetFormatVersion() const;
	u8 GetCaCrlVersion() const;
	u8 GetSignerCrlVersion() const;
	const u8* GetEncryptedTitleKey() const;
	const u8* GetTitleKey(const u8* common_key);
	u64 GetTicketId() const;
	bool IsTicketAssociatedWithDevice() const;
	u32 GetDeviceId() const;
	u64 GetTitleId() const;
	u16 GetTitleVersion() const;
	ESLicenseType GetLicenseType() const;
	ESItemRight GetItemRight() const;
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

	struct sTicketBodyVersion1
	{
		char signature_issuer[kSignatureIssuerLen];
		u8 ecdsa_public_key[kEcdsaPublicKeyLen];
		u8 format_version;
		u8 ca_crl_version;
		u8 signer_crl_version;
		u8 encrypted_title_key[Crypto::kAes128KeySize];
		u8 reserved0;
		u64 ticket_id;
		u32 device_id;
		u64 title_id;
		u8 reserved1[2];
		u16 title_version;
		u8 reserved2[8];
		u8 license_type_item_right; // license_type lower 4 bits, item_right upper 4 bits
		u8 common_key_index;
		u8 reserved3[0x2A];
		u32 eshop_account_id;
		u8 reserved4;
		u8 audit;
		u8 reserved5[0x42];
		sLimit limits[ES_MAX_LIMIT_TYPE];
	};

	struct sContentIndexChunkHeader
	{
		u32 unk0;
		u32 total_size;
		u32 unk1;
		u32 unk2;
		u32 unk3;
		u32 header_size;
		u32 chunk_num;
		u32 chunk_size;
		u32 total_chunks_size;
		u32 unk4;
	};

	struct sContentIndexChunk
	{
		u32 index_high_bits;
		u8 index_bits[kContentIndexBlockSize];
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// serialised data staging ground
	sTicketBodyVersion1 ticket_body_;
	sContentIndexChunkHeader content_mask_header_;
	std::vector<sContentIndexChunk> content_mask_chunks_;

	// serialised data get interface
	inline const char* signature_issuer() const { return ticket_body_.signature_issuer; }
	inline const u8* ecdsa_public_key() const { return ticket_body_.ecdsa_public_key; }
	inline u8 format_version() const { return ticket_body_.format_version; }
	inline u8 ca_crl_version() const { return ticket_body_.ca_crl_version; }
	inline u8 signer_crl_version() const { return ticket_body_.signer_crl_version; }
	inline const u8* encrypted_title_key() const { return ticket_body_.encrypted_title_key; }
	inline u64 ticket_id() const { return be_dword(ticket_body_.ticket_id); }
	inline u32 device_id() const { return be_word(ticket_body_.device_id); }
	inline u64 title_id() const { return be_dword(ticket_body_.title_id); }
	inline u16 title_version() const { return be_hword(ticket_body_.title_version); }
	inline ESLicenseType license_type() const { return (ESLicenseType)(ticket_body_.license_type_item_right & ES_LICENSE_MASK); }
	inline ESItemRight item_right() const { return (ESItemRight)((ticket_body_.license_type_item_right >> 4) & ES_LICENSE_MASK); }
	inline u8 common_key_index() const { return ticket_body_.common_key_index; }
	inline u32 eshop_account_id() const { return be_word(ticket_body_.eshop_account_id); }
	inline u8 audit() const { return ticket_body_.audit; }
	inline ESLimitCode limit_id(u8 index) const { return (ESLimitCode)be_word(ticket_body_.limits[index].id); }
	inline u32 limit_value(u8 index) const { return be_word(ticket_body_.limits[index].value); }

	inline u32 content_mask_total_size() const { return be_word(content_mask_header_.total_size); }
	inline u32 content_mask_header_size() const { return be_word(content_mask_header_.header_size); }
	inline u32 content_mask_entry_num() const { return be_word(content_mask_header_.chunk_num); }
	inline u32 content_mask_entry_size() const { return be_word(content_mask_header_.chunk_size); }
	inline u32 content_mask_total_entry_size() const { return be_word(content_mask_header_.total_chunks_size); }

	inline u32 content_index_chunk_high_bits(const sContentIndexChunk& chunk) const { return be_word(chunk.index_high_bits); }
	inline bool is_content_index_chunk_lower_bits_set(const sContentIndexChunk& chunk, u32 index) const { return (chunk.index_bits[get_content_index_lower_bits(index) / 8] & BIT(index % 8)) != 0; }

	// serialised data set interface
	inline void set_signature_issuer(const char* issuer, int len) { memset(ticket_body_.signature_issuer, 0, kSignatureIssuerLen); memcpy(ticket_body_.signature_issuer, issuer, len < kSignatureIssuerLen ? len : kSignatureIssuerLen); }
	inline void set_ecdsa_public_key(const u8 ecdsa_public_key[kEcdsaPublicKeyLen]) { memcpy(ticket_body_.ecdsa_public_key, ecdsa_public_key, kEcdsaPublicKeyLen); }
	inline void set_format_version(u8 format_version) { ticket_body_.format_version = format_version; }
	inline void set_ca_crl_version(u8 ca_crl_version) { ticket_body_.ca_crl_version = ca_crl_version; }
	inline void set_signer_crl_version(u8 signer_crl_version) { ticket_body_.signer_crl_version = signer_crl_version; }
	inline void set_encrypted_title_key(const u8 encrypted_title_key[Crypto::kAes128KeySize]) { memcpy(ticket_body_.encrypted_title_key, encrypted_title_key, Crypto::kAes128KeySize); }
	inline void set_ticket_id(u64 ticket_id) { ticket_body_.ticket_id = be_dword(ticket_id); }
	inline void set_device_id(u32 device_id) { ticket_body_.device_id = be_word(device_id); }
	inline void set_title_id(u64 title_id) { ticket_body_.title_id = be_dword(title_id); }
	inline void set_title_version(u16 title_version) { ticket_body_.title_version = be_hword(title_version); }
	inline void set_license_type(ESLicenseType license_type) { ticket_body_.license_type_item_right &= ~ES_LICENSE_MASK; ticket_body_.license_type_item_right |= (license_type & ES_LICENSE_MASK); }
	inline void set_item_right(ESItemRight item_right) { ticket_body_.license_type_item_right &= ~(ES_LICENSE_MASK << 4); ticket_body_.license_type_item_right |= ((item_right & ES_LICENSE_MASK) << 4); }
	inline void set_common_key_index(u8 common_key_index) { ticket_body_.common_key_index = common_key_index; }
	inline void set_eshop_account_id(u32 eshop_account_id) { ticket_body_.eshop_account_id = be_word(eshop_account_id); }
	inline void set_audit(u8 audit) { ticket_body_.audit = audit; }
	inline void set_limit(u8 index, ESLimitCode limit_code, u32 value) { ticket_body_.limits[index].id = be_word(limit_code); ticket_body_.limits[index].value = be_word(value);}

	inline void set_content_mask_total_size(u32 total_size) { content_mask_header_.total_size = be_word(total_size); }
	inline void set_content_mask_header_size(u32 header_size) { content_mask_header_.header_size = be_word(header_size); }
	inline void set_content_mask_entry_num(u32 chunk_num) { content_mask_header_.chunk_num = be_word(chunk_num); }
	inline void set_content_mask_entry_size(u32 chunk_size) { content_mask_header_.chunk_size = be_word(chunk_size); }
	inline void set_content_mask_total_entry_size(u32 total_chunks_size) { content_mask_header_.total_chunks_size = be_word(total_chunks_size); }
	inline void set_content_mask_unk0(u32 value) { content_mask_header_.unk0 = be_word(value); }
	inline void set_content_mask_unk1(u32 value) { content_mask_header_.unk1 = be_word(value); }
	inline void set_content_mask_unk2(u32 value) { content_mask_header_.unk2 = be_word(value); }
	inline void set_content_mask_unk3(u32 value) { content_mask_header_.unk3 = be_word(value); }
	inline void set_content_mask_unk4(u32 value) { content_mask_header_.unk4 = be_word(value); }


	inline void set_content_mask_chunk_id(sContentIndexChunk& chunk, u32 id) { chunk.index_high_bits = be_word(id); }
	inline void set_content_mask_chunk_index_bit(sContentIndexChunk& chunk, u16 index) { chunk.index_bits[get_content_index_lower_bits(index) / 8] |= BIT(index % 8); }
	inline void remove_content_mask_chunk_index_bit(sContentIndexChunk& chunk, u16 index) { chunk.index_bits[get_content_index_lower_bits(index) / 8] &= ~(u8)(BIT(index % 8)); }
	

	// inline utils
	inline u32 get_content_index_upper_bits(u16 index) const { return index & kContentIndexUpperMask; }
	inline u32 get_content_index_lower_bits(u16 index) const { return index & kContentIndexLowerMask; }

	// members for deserialised data
	struct sEsLimit
	{
		ESLimitCode limit_code;
		u32 value;
	};

	std::string issuer_;
	u8 format_version_;
	u8 ca_crl_version_;
	u8 signer_crl_version_;
	u8 enc_title_key_[Crypto::kAes128KeySize];
	u8 dec_title_key_[Crypto::kAes128KeySize];
	u64 ticket_id_;
	u32 device_id_;
	u64 title_id_;
	u16 title_version_;
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
	void CreateTitleKeyIv(u64 title_id, u8 iv[Crypto::kAesBlockSize]);
	void EncryptTitleKey(const u8 title_key[Crypto::kAes128KeySize], u64 title_id, const u8 common_key[Crypto::kAes128KeySize], u8 enc_title_key[Crypto::kAes128KeySize]);
	void DecryptTitleKey(const u8 enc_title_key[Crypto::kAes128KeySize], u64 title_id, const u8 common_key[Crypto::kAes128KeySize], u8 title_key[Crypto::kAes128KeySize]);
	void ClearContentIndexControlEntry(struct sContentIndexChunk& entry);
	void AddContentIndexChunk(u32 id);
	sContentIndexChunk& GetContentIndexChunk(u32 id);

	// (De)serialiser
	void HashSerialisedData(EsCrypto::EsSignType sign_type, u8* hash) const;
	void SerialiseWithoutSign(EsCrypto::EsSignType sign_type);
	void SerialiseTicketBody();
	void SerialiseContentMaskChunks();
	void SerialiseContentMaskHeader();

	void DeserialiseTicketBody();
	void DeserialiseContentMask();

	bool IsSupportedFormatVersion(u8 version) const;

	void ClearDeserialisedVariables();
};

