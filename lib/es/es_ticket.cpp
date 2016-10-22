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


void EsTicket::HashSerialisedData(EsCrypto::EsSignType sign_type, u8 * hash) const
{
	size_t data_size = 0;
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);
	if (format_version_ == ES_TIK_VER_0)
	{
		data_size = sizeof(sTicketBody_v0);
	}
	else if (format_version_ == ES_TIK_VER_1)
	{
		const sContentIndexChunkHeader* cntHdr = (const sContentIndexChunkHeader*)(serialised_data_.data_const() + sign_size + sizeof(sTicketBody_v1));
		data_size = sizeof(sTicketBody_v1) + cntHdr->total_size();
	}
	
	EsCrypto::HashData(sign_type, serialised_data_.data_const() + sign_size, data_size, hash);
}

void EsTicket::SerialiseWithoutSign_v0(EsCrypto::EsSignType sign_type)
{
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);

	// serialised data staging ground
	sTicketBody_v0 body;

	// serialise body
	body.set_issuer(issuer_.c_str(), strlen(issuer_.c_str()));
	body.set_format_version(ES_TIK_VER_0);
	body.set_ca_crl_version(ca_crl_version_);
	body.set_signer_crl_version(signer_crl_version_);
	if (is_common_key_set_)
	{
		EncryptTitleKey(dec_title_key_, title_id_, common_key_, enc_title_key_);
	}
	body.set_encrypted_title_key(enc_title_key_);
	body.set_ticket_id(ticket_id_);
	body.set_device_id(device_id_);
	body.set_title_id(title_id_);
	body.set_system_title_access_mask(system_title_access_mask_);
	body.set_title_version(title_version_);
	body.set_access_title_id(access_title_id_);
	body.set_access_title_id_mask(access_title_id_mask_);
	body.set_license_type(license_type_);
	body.set_key_id(common_key_index_);
	body.set_audit(audit_);
	for (size_t i = 0; i < limits_.size() && i < ES_MAX_LIMIT_TYPE; i++)
	{
		body.set_limit(i, limits_[i].limit_code, limits_[i].value);
	}
	for (u16 index : enabled_content_)
	{
		body.enable_content_index(index);
		
	}

	size_t ticket_size = sign_size + sizeof(sTicketBody_v0);

	// allocate memory for serialised data
	if (serialised_data_.alloc(ticket_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for ticket");
	}

	// copy body from staging ground into serialised data buffer
	memcpy(serialised_data_.data() + sign_size, &body, sizeof(sTicketBody_v0));
}

void EsTicket::SerialiseWithoutSign_v1(EsCrypto::EsSignType sign_type)
{
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);

	// serialised data staging ground
	sTicketBody_v1 body;
	sContentIndexChunkHeader cntHdr;
	std::vector<sContentIndexChunk> cntList;

	// serialise body
	body.set_issuer(issuer_.c_str(), strlen(issuer_.c_str()));
	body.set_format_version(ES_TIK_VER_1);
	body.set_ca_crl_version(ca_crl_version_);
	body.set_signer_crl_version(signer_crl_version_);
	if (is_common_key_set_)
	{
		EncryptTitleKey(dec_title_key_, title_id_, common_key_, enc_title_key_);
	}
	body.set_encrypted_title_key(enc_title_key_);
	body.set_ticket_id(ticket_id_);
	body.set_device_id(device_id_);
	body.set_title_id(title_id_);
	body.set_title_version(title_version_);
	body.set_license_type(license_type_);
	body.set_key_id(common_key_index_);
	body.set_eshop_account_id(eshop_account_id_);
	for (size_t i = 0; i < limits_.size() && i < ES_MAX_LIMIT_TYPE; i++)
	{
		body.set_limit(i, limits_[i].limit_code, limits_[i].value);
	}

	// serialise content mask chunks
	for (u16 index : enabled_content_)
	{
		bool isIndexSet = false;
		for (auto& cnt : cntList)
		{
			// if the index group is for the current index, set the index bit
			if (cnt.index_group() == cnt.get_index_high_bits(index)) 
			{
				cnt.enable_index(index);
				isIndexSet = true;
				break;
			}
		}
		// if chunk doesn't exist, create it
		if (isIndexSet == false)
		{
			sContentIndexChunk cnt;
			cnt.set_index_group(index);
			cnt.enable_index(index);

			// add to list
			cntList.push_back(cnt);
		}
	}

	// serialise content mask header
	cntHdr.set_header_size(sizeof(sContentIndexChunkHeader));
	cntHdr.set_chunk_num(cntList.size());
	cntHdr.set_chunk_size(sizeof(sContentIndexChunk));
	cntHdr.set_total_chunks_size(cntHdr.chunk_size() * sizeof(sContentIndexChunk));
	cntHdr.set_total_size(cntHdr.header_size() + cntHdr.total_chunks_size());
	cntHdr.set_unk0(sContentIndexChunkHeader::kUnk0Default);
	cntHdr.set_unk1(sContentIndexChunkHeader::kUnk1Default);
	cntHdr.set_unk2(sContentIndexChunkHeader::kUnk2Default);
	cntHdr.set_unk3(sContentIndexChunkHeader::kUnk3Default);
	cntHdr.set_unk4(sContentIndexChunkHeader::kUnk4Default);

	size_t ticket_size = sign_size + sizeof(sTicketBody_v1) + cntHdr.total_size();

	// allocate memory for serialised data
	if (serialised_data_.alloc(ticket_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for ticket");
	}

	// copy components from staging ground into serialised data buffer
	memcpy(serialised_data_.data() + sign_size, &body, sizeof(sTicketBody_v1));
	memcpy(serialised_data_.data() + sign_size + sizeof(sTicketBody_v1), &cntHdr, sizeof(sContentIndexChunkHeader));

	sContentIndexChunk* chunk_ptr = (sContentIndexChunk*)(serialised_data_.data() + sign_size + sizeof(sTicketBody_v1) + sizeof(sContentIndexChunkHeader));
	for (size_t i = 0; i < cntList.size(); i++)
	{
		memcpy(&chunk_ptr[i], &cntList[i], sizeof(sContentIndexChunk));
	}
}

u8 EsTicket::GetRawBinaryFormatVersion(const u8 * raw_tik_body)
{
	return raw_tik_body[0x7C];
}

void EsTicket::Deserialise_v0(const u8 * tik_data)
{
	// cache body pointer
	const u8* tik_body = (const u8*)EsCrypto::GetSignedBinaryBody(tik_data);

	// get tik body
	const sTicketBody_v0* body = (const sTicketBody_v0*)tik_body;
	
	// save internal copy of ticket
	size_t tik_size = EsCrypto::GetSignatureSize(tik_data) + sizeof(sTicketBody_v0);
	if (serialised_data_.alloc(tik_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for tik");
	}
	memcpy(serialised_data_.data(), tik_data, tik_size);

	// deserialised body
	issuer_ = std::string(body->issuer(), (strlen(body->issuer()) < kSignatureIssuerLen ? strlen(body->issuer()) : kSignatureIssuerLen));
	server_public_key_ = *body->server_public_key();
	format_version_ = body->format_version();
	ca_crl_version_ = body->ca_crl_version();
	signer_crl_version_ = body->signer_crl_version();
	memcpy(enc_title_key_, body->encrypted_title_key(), Crypto::kAes128KeySize);
	ticket_id_ = body->ticket_id();
	device_id_ = body->device_id();
	title_id_ = body->title_id();
	system_title_access_mask_ = body->system_title_access_mask();
	title_version_ = body->title_version();
	access_title_id_ = body->access_title_id();
	access_title_id_mask_ = body->access_title_id_mask();
	license_type_ = body->license_type();
	common_key_index_ = body->key_id();
	audit_ = body->audit();
	for (int i = 0; i < ES_MAX_LIMIT_TYPE; i++)
	{
		if (body->limit_code(i) == 0)
		{
			break;
		}

		sEsLimit limit{ body->limit_code(i), body->limit_value(i) };
		limits_.push_back(limit);
	}

	// save content indexes
	for (u32 i = 0; i < kEnabledIndexMax_v0; i++)
	{
		if (body->is_content_enabled(i))
		{
			enabled_content_.push_back(i);
		}
	}
}

void EsTicket::Deserialise_v1(const u8 * tik_data)
{
	// cache body pointer
	const u8* tik_body = (const u8*)EsCrypto::GetSignedBinaryBody(tik_data);

	// get tik body
	const sTicketBody_v1* body = (const sTicketBody_v1*)tik_body;
	const sContentIndexChunkHeader* cntHdr = (const sContentIndexChunkHeader*)(tik_body + sizeof(sTicketBody_v1));
	const sContentIndexChunk* cntList = (const sContentIndexChunk*)(tik_body + sizeof(sTicketBody_v1) + sizeof(sContentIndexChunkHeader));

	// save internal copy of ticket
	size_t tik_size = EsCrypto::GetSignatureSize(tik_data) + sizeof(sTicketBody_v1) + cntHdr->total_size();
	if (serialised_data_.alloc(tik_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for ticket");
	}
	memcpy(serialised_data_.data(), tik_data, tik_size);

	// deserialised body
	issuer_ = std::string(body->issuer(), (strlen(body->issuer()) < kSignatureIssuerLen ? strlen(body->issuer()) : kSignatureIssuerLen));
	server_public_key_ = *body->server_public_key();
	format_version_ = body->format_version();
	ca_crl_version_ = body->ca_crl_version();
	signer_crl_version_ = body->signer_crl_version();
	memcpy(enc_title_key_, body->encrypted_title_key(), Crypto::kAes128KeySize);
	ticket_id_ = body->ticket_id();
	device_id_ = body->device_id();
	title_id_ = body->title_id();
	title_version_ = body->title_version();
	license_type_ = body->license_type();
	common_key_index_ = body->key_id();
	eshop_account_id_ = body->eshop_account_id();
	for (int i = 0; i < ES_MAX_LIMIT_TYPE; i++)
	{
		if (body->limit_code(i) == 0)
		{
			break;
		}

		sEsLimit limit{ body->limit_code(i), body->limit_value(i) };
		limits_.push_back(limit);
	}

	// check content index header
	if (cntHdr->unk0() != sContentIndexChunkHeader::kUnk0Default ||
		cntHdr->unk1() != sContentIndexChunkHeader::kUnk1Default ||
		cntHdr->unk2() != sContentIndexChunkHeader::kUnk2Default ||
		cntHdr->unk3() != sContentIndexChunkHeader::kUnk3Default ||
		cntHdr->unk4() != sContentIndexChunkHeader::kUnk4Default ||
		cntHdr->header_size() != sizeof(sContentIndexChunkHeader) ||
		cntHdr->chunk_size() != sizeof(sContentIndexChunk) ||
		cntHdr->total_chunks_size() != (cntHdr->chunk_num() * cntHdr->chunk_size()) ||
		cntHdr->total_size() != (cntHdr->header_size() + cntHdr->total_chunks_size()))
	{
		throw ProjectSnakeException(kModuleName, "Ticket \"Enabled content index\" structure is malformed");
	}

	// save content indexes
	u16 index_group;
	for (u32 i = 0; i < cntHdr->chunk_num(); i++)
	{
		index_group = cntList[i].index_group();
		for (u16 index_low_bits = 0; index_low_bits <= kContentIndexLowerMask; index_low_bits++)
		{
			if (cntList[i].is_index_enabled(index_group | index_low_bits))
			{
				enabled_content_.push_back(index_group | index_low_bits);
			}
		}
	}
}

bool EsTicket::IsSupportedFormatVersion(u8 version) const
{
	return version == ES_TIK_VER_0 || version == ES_TIK_VER_1;
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

	// cache body ptr
	const u8* tik_body = (const u8*)EsCrypto::GetSignedBinaryBody(ticket_data);

	// initial es signature header check
	if (tik_body == nullptr)
	{
		throw ProjectSnakeException(kModuleName, "Ticket is corrupt (bad signature identifier)");
	}

	// deserialise tmd based on version
	u8 format_version = GetRawBinaryFormatVersion(tik_body);
	if (format_version == ES_TIK_VER_0)
	{
		Deserialise_v0(ticket_data);
	}
	else if (format_version == ES_TIK_VER_1)
	{
		Deserialise_v1(ticket_data);
	}
	else {
		throw ProjectSnakeException(kModuleName, "Unsupported ticket format version");
	}
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

const Crypto::sEccPoint& EsTicket::GetServerPublicKey() const
{
	return server_public_key_;
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

u16 EsTicket::GetSystemAccessMask() const
{
	return system_title_access_mask_;
}

u16 EsTicket::GetTitleVersion() const
{
	return title_version_;
}

u32 EsTicket::GetAccessTitleId() const
{
	return access_title_id_;
}

u32 EsTicket::GetAccessTitleIdMask() const
{
	return access_title_id_mask_;
}

EsTicket::ESLicenseType EsTicket::GetLicenseType() const
{
	return license_type_;
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
	SerialiseTicket(private_key, ES_TIK_VER_1);
}

void EsTicket::SerialiseTicket(const Crypto::sRsa2048Key & private_key, ESTicketFormatVersion format)
{
	// sign parameters
	EsCrypto::EsSignType sign_type;

	// serialise
	if (format == ES_TIK_VER_0)
	{
		sign_type = EsCrypto::ES_SIGN_RSA2048_SHA1;
		SerialiseWithoutSign_v0(sign_type);
	}
	else if (format == ES_TIK_VER_1)
	{
		sign_type = EsCrypto::ES_SIGN_RSA2048_SHA256;
		SerialiseWithoutSign_v1(sign_type);
	}

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
	SerialiseTicket(private_key, ES_TIK_VER_1);
}

void EsTicket::SerialiseTicket(const Crypto::sRsa4096Key& private_key, ESTicketFormatVersion format)
{
	// sign parameters
	EsCrypto::EsSignType sign_type;

	// serialise
	if (format == ES_TIK_VER_0)
	{
		sign_type = EsCrypto::ES_SIGN_RSA2048_SHA1;
		//SerialiseWithoutSign_v0(sign_type);
	}
	else if (format == ES_TIK_VER_1)
	{
		sign_type = EsCrypto::ES_SIGN_RSA2048_SHA256;
		SerialiseWithoutSign_v1(sign_type);
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Unsupported eTicket version: " + format);
	}

	// sign the serialised data
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	if (EsCrypto::RsaSign(sign_type, hash, private_key.modulus, private_key.priv_exponent, serialised_data_.data()) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to sign eTicket");
	}
}

void EsTicket::SetIssuer(const std::string & issuer)
{
	if (issuer_.size() > kSignatureIssuerLen)
	{
		throw ProjectSnakeException(kModuleName, "ETicket issuer length is too large");
	}

	issuer_ = std::string(issuer);
}

void EsTicket::SetServerPublicKey(const Crypto::sEccPoint & public_key)
{
	server_public_key_ = public_key;
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

void EsTicket::SetSystemAccessMask(u16 system_access_mask)
{
	system_title_access_mask_ = system_access_mask;
}

void EsTicket::SetTitleVersion(u16 title_version)
{
	title_version_ = title_version;
}

void EsTicket::SetAccessTitleId(u32 access_title_id)
{
	access_title_id_ = access_title_id;
}

void EsTicket::SetAccessTitleIdMask(u32 access_title_id_mask)
{
	access_title_id_mask_ = access_title_id_mask;
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
		throw ProjectSnakeException(kModuleName, "Too many eTicket limits (Maximum: 8)");
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
