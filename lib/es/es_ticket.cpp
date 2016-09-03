#include "es_ticket.h"
#include "es_crypto.h"


EsTicket::EsTicket() :
	serialised_data_()
{
	ClearDeserialisedVariables();
}


EsTicket::~EsTicket()
{
}

void EsTicket::operator=(const EsTicket & other)
{
	DeserialiseTicket(other.GetSerialisedData());
}

const u8* EsTicket::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t EsTicket::GetSerialisedDataSize() const 
{
	return serialised_data_.size();
}

void EsTicket::CreateTitleKeyIv(u64 title_id, u8 iv[Crypto::kAesBlockSize])
{
	memset(iv, 0, Crypto::kAesBlockSize);
	for (size_t i = 0; i < sizeof(u64); i++)
	{
		iv[i] = (title_id >> (56 - i * 8)) & 0xff;
	}
}

void EsTicket::EncryptTitleKey(const u8 title_key[Crypto::kAes128KeySize], u64 title_id, const u8 common_key[Crypto::kAes128KeySize], u8 enc_title_key[Crypto::kAes128KeySize])
{
	u8 iv[Crypto::kAesBlockSize];
	CreateTitleKeyIv(title_id, iv);
	Crypto::AesCbcEncrypt(title_key, Crypto::kAes128KeySize, common_key, iv, enc_title_key);
}

void EsTicket::DecryptTitleKey(const u8 enc_title_key[Crypto::kAes128KeySize], u64 title_id, const u8 common_key[Crypto::kAes128KeySize], u8 title_key[Crypto::kAes128KeySize])
{
	u8 iv[Crypto::kAesBlockSize];
	CreateTitleKeyIv(title_id, iv);
	Crypto::AesCbcDecrypt(enc_title_key, Crypto::kAes128KeySize, common_key, iv, title_key);
}

void EsTicket::ClearContentIndexControlEntry(sContentIndexChunk & entry)
{
	entry.index_high_bits = 0;
	memset(entry.index_bits, 0, kContentIndexBlockSize);
}

void EsTicket::AddContentIndexChunk(u32 id)
{
	sContentIndexChunk chunk;
	
	// clear
	ClearContentIndexControlEntry(chunk);

	// set id
	set_content_mask_chunk_id(chunk, id);

	// Add
	content_mask_chunks_.push_back(chunk);
}

EsTicket::sContentIndexChunk& EsTicket::GetContentIndexChunk(u32 id)
{
	// find existing
	for (auto& chunk : content_mask_chunks_)
	{
		if (content_index_chunk_high_bits(chunk) == id)
		{
			return chunk;
		}
	}

	// else create
	AddContentIndexChunk(id);

	// recursive call itself now we know it exists
	return GetContentIndexChunk(id);
}

void EsTicket::HashSerialisedData(EsCrypto::EsSignType sign_type, u8 * hash) const
{
	size_t data_size = sizeof(sTicketBodyVersion1) + content_mask_total_size();
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);
	EsCrypto::HashData(sign_type, serialised_data_.data_const() + sign_size, data_size, hash);
}

void EsTicket::SerialiseWithoutSign(EsCrypto::EsSignType sign_type)
{
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);

	// initial check until version0 is supported
	if (!IsSupportedFormatVersion(format_version_))
	{
		throw ProjectSnakeException(kModuleName, "Unsupported ticket format version");
	}

	// serialise components
	SerialiseTicketBody();
	SerialiseContentMaskChunks();
	SerialiseContentMaskHeader();

	size_t ticket_size = sign_size + sizeof(sTicketBodyVersion1) + content_mask_total_size();

	// allocate memory for serialised data
	if (serialised_data_.alloc(ticket_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for ticket");
	}

	// copy components from staging ground into serialised data buffer
	memcpy(serialised_data_.data() + sign_size, &ticket_body_, sizeof(sTicketBodyVersion1));
	memcpy(serialised_data_.data() + sign_size + sizeof(sTicketBodyVersion1), &content_mask_header_, sizeof(sContentIndexChunkHeader));

	sContentIndexChunk* chunk_ptr = (sContentIndexChunk*)(serialised_data_.data() + sign_size + sizeof(sTicketBodyVersion1) + sizeof(sContentIndexChunkHeader));
	for (size_t i = 0; i < content_mask_chunks_.size(); i++)
	{
		memcpy(&chunk_ptr[i], &content_mask_chunks_[i], sizeof(sContentIndexChunk));
	}
}

void EsTicket::SerialiseTicketBody()
{
	// clear struct
	memset(&ticket_body_, 0, sizeof(sTicketBodyVersion1));
	
	// set data
	set_signature_issuer(issuer_.c_str(), strlen(issuer_.c_str()));
	set_format_version(format_version_);
	set_ca_crl_version(ca_crl_version_);
	set_signer_crl_version(signer_crl_version_);
	// if common key was set, encrypt the title key
	if (is_common_key_set_)
	{
		EncryptTitleKey(dec_title_key_, title_id_, common_key_, enc_title_key_);
	}
	set_encrypted_title_key(enc_title_key_);
	set_ticket_id(ticket_id_);
	set_device_id(device_id_);
	set_title_id(title_id_);
	set_title_version(title_version_);
	set_license_type(license_type_);
	set_item_right(item_right_);
	set_common_key_index(common_key_index_);
	set_eshop_account_id(eshop_account_id_);
	set_audit(audit_);
	for (size_t i = 0; i < limits_.size() && i < ES_MAX_LIMIT_TYPE; i++)
	{
		set_limit(i, limits_[i].limit_code, limits_[i].value);
	}
}

void EsTicket::SerialiseContentMaskChunks()
{
	for (u16 index : enabled_content_)
	{
		set_content_mask_chunk_index_bit(GetContentIndexChunk(get_content_index_upper_bits(index)), index);
	}
}

void EsTicket::SerialiseContentMaskHeader()
{
	// clear struct
	memset(&content_mask_header_, 0, sizeof(sContentIndexChunkHeader));

	// set data
	set_content_mask_header_size(sizeof(sContentIndexChunkHeader));
	set_content_mask_entry_num(content_mask_chunks_.size());
	set_content_mask_entry_size(sizeof(sContentIndexChunk));
	set_content_mask_total_entry_size(content_mask_chunks_.size() * sizeof(sContentIndexChunk));
	set_content_mask_total_size(content_mask_header_size() + content_mask_total_entry_size());
	set_content_mask_unk0(0x00010014);
	set_content_mask_unk0(0x00000014);
	set_content_mask_unk0(0x00010014);
	set_content_mask_unk0(0x00000000);
	set_content_mask_unk0(0x00030000);
}

void EsTicket::DeserialiseTicketBody()
{
	issuer_ = std::string(signature_issuer());
	format_version_ = format_version();
	ca_crl_version_ = ca_crl_version();
	signer_crl_version_ = signer_crl_version();
	memcpy(enc_title_key_, encrypted_title_key(), Crypto::kAes128KeySize);
	ticket_id_ = ticket_id();
	device_id_ = device_id();
	title_id_ = title_id();
	title_version_ = title_version();
	license_type_ = license_type();
	item_right_ = item_right();
	common_key_index_ = common_key_index();
	eshop_account_id_ = eshop_account_id();
	audit_ = audit();
	for (int i = 0; i < ES_MAX_LIMIT_TYPE; i++)
	{
		if (limit_id(i) == 0)
		{
			break;
		}

		sEsLimit limit{ limit_id(i), limit_value(i) };
		limits_.push_back(limit);
	}
}

void EsTicket::DeserialiseContentMask()
{
	u16 index_high_bits;
	for (const auto& chunk : content_mask_chunks_)
	{
		index_high_bits = content_index_chunk_high_bits(chunk);
		for (u16 index_low_bits = 0; index_low_bits <= kContentIndexLowerMask; index_low_bits++)
		{
			if (is_content_index_chunk_lower_bits_set(chunk, index_low_bits))
			{
				enabled_content_.push_back(index_low_bits | index_high_bits);
			}
		}
	}
}

bool EsTicket::IsSupportedFormatVersion(u8 version) const
{
	return version == kFormatVersion;
}

void EsTicket::ClearDeserialisedVariables()
{
	issuer_.clear();
	format_version_ = kFormatVersion;
	ca_crl_version_ = kCaCrlVersion;
	signer_crl_version_ = kSignerCrlVersion;
	memset(enc_title_key_, 0, Crypto::kAes128KeySize);
	memset(dec_title_key_, 0, Crypto::kAes128KeySize);
	ticket_id_ = 0;
	device_id_ = 0;
	title_id_ = 0;
	title_version_ = 0;
	license_type_ = (ESLicenseType)0;
	item_right_ = (ESItemRight)0;
	common_key_index_ = 0;
	eshop_account_id_ = 0;
	audit_ = 0;
	limits_.clear();
	enabled_content_.clear();

	is_common_key_set_ = false;
	memset(common_key_, 0, Crypto::kAes128KeySize);
}

void EsTicket::DeserialiseTicket(const u8* ticket_data)
{
	ClearDeserialisedVariables();

	// initial es signature header check
	if (EsCrypto::GetSignedBinaryBody(ticket_data) == nullptr)
	{
		throw ProjectSnakeException(kModuleName, "Ticket is corrupt (bad signature identifier)");
	}
	
	// cache pointer
	const u8* ticket_body = (const u8*)EsCrypto::GetSignedBinaryBody(ticket_data);

	// copy ticket body into staging ground
	memcpy(&ticket_body_, ticket_body, sizeof(sTicketBodyVersion1));

	// confirm supported format version
	if (!IsSupportedFormatVersion(format_version()))
	{
		throw ProjectSnakeException(kModuleName, "Unsupported ticket format version");
	}

	// copy content mask header
	memcpy(&content_mask_header_, ticket_body + sizeof(sTicketBodyVersion1), sizeof(sContentIndexChunkHeader));

	// copy content mask chunks
	sContentIndexChunk* chunk_ptr = (sContentIndexChunk*)(ticket_body + sizeof(sTicketBodyVersion1) + sizeof(sContentIndexChunkHeader));
	for (u32 i = 0; i < content_mask_entry_num(); i++)
	{
		content_mask_chunks_.push_back(chunk_ptr[i]);
	}
	
	// save intenal copy of ticket
	size_t ticket_size = EsCrypto::GetSignatureSize(ticket_data) + sizeof(sTicketBodyVersion1) + content_mask_total_size();
	
	// allocate memory for serialised data
	if (serialised_data_.alloc(ticket_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for ticket");
	}

	memcpy(serialised_data_.data(), ticket_data, ticket_size);

	// deserialise data
	DeserialiseTicketBody();
	DeserialiseContentMask();
}

bool EsTicket::ValidateSignature(const Crypto::sRsa2048Key & key) const
{
	EsCrypto::EsSignType sign_type = EsCrypto::GetSignatureType(serialised_data_.data_const());
	if (!EsCrypto::IsSignRsa2048(sign_type))
	{
		throw ProjectSnakeException(kModuleName, "Attempted to validate signature with incompatible key");
	}

	// signature check
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	return EsCrypto::RsaVerify(hash, key.modulus, serialised_data_.data_const()) == 0;
}

bool EsTicket::ValidateSignature(const Crypto::sRsa4096Key & key) const
{
	EsCrypto::EsSignType sign_type = EsCrypto::GetSignatureType(serialised_data_.data_const());
	if (!EsCrypto::IsSignRsa4096(sign_type))
	{
		throw ProjectSnakeException(kModuleName, "Attempted to validate signature with incompatible key");
	}

	// signature check
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	return EsCrypto::RsaVerify(hash, key.modulus, serialised_data_.data_const()) == 0;
}

bool EsTicket::ValidateSignature(const EsCert & signer) const
{
	EsCrypto::EsSignType sign_type = EsCrypto::GetSignatureType(serialised_data_.data_const());

	if (signer.GetChildIssuer() != GetIssuer())
	{
		//throw ProjectSnakeException(kModuleName, "Failed to verify ticket using parent certificate: is not parent");
		return false;
	}

	bool is_valid = false;
	if (signer.GetPublicKeyType() == EsCert::RSA_2048 && EsCrypto::IsSignRsa2048(sign_type))
	{
		Crypto::sRsa2048Key rsa_key;
		signer.GetPublicKey(rsa_key);
		is_valid = ValidateSignature(rsa_key);
	}
	else if (signer.GetPublicKeyType() == EsCert::RSA_4096 && EsCrypto::IsSignRsa4096(sign_type))
	{
		Crypto::sRsa4096Key rsa_key;
		signer.GetPublicKey(rsa_key);
		is_valid = ValidateSignature(rsa_key);
	}
	else if (signer.GetPublicKeyType() == EsCert::ECDSA && EsCrypto::IsSignEcdsa(sign_type))
	{
		throw ProjectSnakeException(kModuleName, "Failed to verify ticket using parent certificate: ECDSA not implemented");
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Failed to verify ticket using parent certificate: public key / signature type mismatch");
	}

	return is_valid;
}

const std::string & EsTicket::GetIssuer() const
{
	return issuer_;
}

u8 EsTicket::GetFormatVersion() const
{
	return format_version_;
}

u8 EsTicket::GetCaCrlVersion() const
{
	return ca_crl_version_;
}

u8 EsTicket::GetSignerCrlVersion() const
{
	return signer_crl_version_;
}

const u8* EsTicket::GetEncryptedTitleKey() const
{
	return enc_title_key_;
}

const u8* EsTicket::GetTitleKey(const u8* common_key)
{
	if (common_key == NULL)
	{
		// TODO
		return nullptr;
	}

	DecryptTitleKey(enc_title_key_, title_id_, common_key, dec_title_key_);

	return dec_title_key_;
}

u64 EsTicket::GetTicketId() const
{
	return ticket_id_;
}

bool EsTicket::IsTicketAssociatedWithDevice() const
{
	return device_id_ != 0;
}

u32 EsTicket::GetDeviceId() const
{
	return device_id_;
}

u64 EsTicket::GetTitleId() const
{
	return title_id_;
}

u16 EsTicket::GetTitleVersion() const
{
	return title_version_;
}

EsTicket::ESLicenseType EsTicket::GetLicenseType() const
{
	return license_type_;
}

EsTicket::ESItemRight EsTicket::GetItemRight() const
{
	return item_right_;
}

u8 EsTicket::GetCommonKeyIndex() const
{
	return common_key_index_;
}

bool EsTicket::IsTicketAssociatedWithEShopAccount() const
{
	return eshop_account_id_ != 0;
}

u32 EsTicket::GetEShopAccountId() const
{
	return eshop_account_id_;
}

u8 EsTicket::GetAudit() const
{
	return audit_;
}

bool EsTicket::IsLimitSet(ESLimitCode limit_code) const
{
	bool found = false;
	for (size_t i = 0; i < limits_.size(); i++)
	{
		if (limits_[i].limit_code == limit_code)
		{
			found = true;
		}
	}
	return found;
}

u32 EsTicket::GetLimit(ESLimitCode limit_code) const
{
	u32 value = 0;
	for (size_t i = 0; i < limits_.size(); i++)
	{
		if (limits_[i].limit_code == limit_code)
		{
			value = limits_[i].value;
		}
	}
	return value;
}

bool EsTicket::IsContentEnabled(u16 content_index) const
{
	bool is_enabled = false;
	for (size_t i = 0; i < enabled_content_.size(); i++)
	{
		if (enabled_content_[i] == content_index)
		{
			is_enabled = true;
		}
	}
	return is_enabled;
}

const std::vector<u16>& EsTicket::GetEnabledContentList() const
{
	return enabled_content_;
}

void EsTicket::SerialiseTicket(const Crypto::sRsa2048Key & private_key)
{
	SerialiseTicket(private_key, false);
}

void EsTicket::SerialiseTicket(const Crypto::sRsa2048Key & private_key, bool use_sha1)
{
	// sign parameters
	EsCrypto::EsSignType sign_type = use_sha1 ? EsCrypto::ES_SIGN_RSA2048_SHA1 : EsCrypto::ES_SIGN_RSA2048_SHA256;

	// serialise
	SerialiseWithoutSign(sign_type);

	// sign the serialised data
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	if (EsCrypto::RsaSign(sign_type, hash, private_key.modulus, private_key.priv_exponent, serialised_data_.data()) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to sign ticket");
	}
}

void EsTicket::SerialiseTicket(const Crypto::sRsa4096Key & private_key)
{
	SerialiseTicket(private_key, false);
}

void EsTicket::SerialiseTicket(const Crypto::sRsa4096Key& private_key, bool use_sha1)
{
	// sign parameters
	EsCrypto::EsSignType sign_type = use_sha1 ? EsCrypto::ES_SIGN_RSA4096_SHA1 : EsCrypto::ES_SIGN_RSA4096_SHA256;

	// serialise
	SerialiseWithoutSign(sign_type);

	// sign the serialised data
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	if (EsCrypto::RsaSign(sign_type, hash, private_key.modulus, private_key.priv_exponent, serialised_data_.data()) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to sign ticket");
	}
}

void EsTicket::SetIssuer(const std::string & issuer)
{
	if (issuer_.size() > kSignatureIssuerLen)
	{
		throw ProjectSnakeException(kModuleName, "Ticket issuer length is too large");
	}

	issuer_ = std::string(issuer);
}

void EsTicket::SetFormatVersion(u8 version)
{
	format_version_ = version;
}

void EsTicket::SetCaCrlVersion(u8 version)
{
	ca_crl_version_ = version;
}

void EsTicket::SetSignerCrlVersion(u8 version)
{
	signer_crl_version_ = version;
}

void EsTicket::SetEncryptedTitleKey(const u8 enc_title_key[Crypto::kAes128KeySize])
{
	if (enc_title_key == NULL)
	{
		throw ProjectSnakeException(kModuleName, "Null pointer was passed to SetEncryptedTitleKey()");
	}

	memcpy(enc_title_key_, enc_title_key, Crypto::kAes128KeySize);
}

void EsTicket::SetTitleKey(const u8 title_key[Crypto::kAes128KeySize], const u8 common_key[Crypto::kAes128KeySize])
{
	if (title_key == NULL || common_key == NULL)
	{
		throw ProjectSnakeException(kModuleName, "Null pointer was passed to SetTitleKey()");
	}

	memcpy(dec_title_key_, title_key, Crypto::kAes128KeySize);
	memcpy(common_key_, common_key, Crypto::kAes128KeySize);
	is_common_key_set_ = true;
}

void EsTicket::SetTicketId(u64 ticket_id)
{
	ticket_id_ = ticket_id;
}

void EsTicket::SetDeviceId(u32 device_id)
{
	device_id_ = device_id;
}

void EsTicket::SetTitleId(u64 title_id)
{
	title_id_ = title_id;
}

void EsTicket::SetTitleVersion(u16 title_version)
{
	title_version_ = title_version;
}

void EsTicket::SetLicenseType(ESLicenseType license_type)
{
	license_type_ = license_type;
}

void EsTicket::SetCommonKeyIndex(u8 index)
{
	common_key_index_ = index;
}

void EsTicket::SetEShopAccountId(u32 account_id)
{
	eshop_account_id_ = account_id;
}

void EsTicket::SetAudit(u8 audit)
{
	audit_ = audit;
}

void EsTicket::AddLimit(ESLimitCode limit_code, u32 value)
{
	if (limits_.size() >= ES_MAX_LIMIT_TYPE)
	{
		throw ProjectSnakeException(kModuleName, "Too many ticket limits (Maximum: 8)");
	}

	bool exists = false;
	for (size_t i = 0; i < limits_.size(); i++)
	{
		if (limits_[i].limit_code == limit_code)
		{
			exists = true;
			limits_[i].value = value;
		}
	}

	if (exists == false)
	{
		sEsLimit limit;
		limit.limit_code = limit_code;
		limit.value = value;
		limits_.push_back(limit);
	}
}

void EsTicket::RemoveLimit(ESLimitCode limit_code)
{
	for (size_t i = 0; i < limits_.size(); i++)
	{
		if (limits_[i].limit_code == limit_code)
		{
			limits_.erase(limits_.begin() + i);
		}
	}
}

void EsTicket::EnableContent(u16 index)
{
	enabled_content_.push_back(index);
}
