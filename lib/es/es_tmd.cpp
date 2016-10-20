#include "es_tmd.h"
#include "es_crypto.h"


EsTmd::EsTmd()
{
}


EsTmd::~EsTmd()
{
}

void EsTmd::operator=(const EsTmd & other)
{
	DeserialiseTmd(other.GetSerialisedData());
}

const u8* EsTmd::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t EsTmd::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void EsTmd::HashSerialisedData(EsCrypto::EsSignType sign_type, u8* hash) const
{
	size_t data_size = 0;
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);
	if (format_version_ == ES_TMD_VER_0) {
		data_size = sizeof(sTitleMetadataBody_v0) + sizeof(sContentInfo_v0) * content_num_;
	}
	else if (format_version_ == ES_TMD_VER_1) {
		data_size = sizeof(sTitleMetadataBody_v1);
	}

	EsCrypto::HashData(sign_type, serialised_data_.data_const() + sign_size, data_size, hash);
}

void EsTmd::SerialiseWithoutSign_v0(EsCrypto::EsSignType sign_type)
{
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);

	if (content_list_.size() == 0)
	{
		throw ProjectSnakeException(kModuleName, "No content were specified for tmd");
	}

	size_t tmd_size = sign_size + sizeof(sTitleMetadataBody_v0) + sizeof(sContentInfo_v0)* content_list_.size();
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for tmd");
	}

	// serialise content info
	sContentInfo_v0* info_ptr = (sContentInfo_v0*)(serialised_data_.data() + sign_size + sizeof(sTitleMetadataBody_v0));
	for (size_t i = 0; i < content_num_; i++)
	{
		info_ptr[i].set_id(content_list_[i].id);
		info_ptr[i].set_index(content_list_[i].index);
		info_ptr[i].set_flag(content_list_[i].flags);
		info_ptr[i].set_size(content_list_[i].size);
		info_ptr[i].set_hash(content_list_[i].hash);
	}

	// serialise body
	sTitleMetadataBody_v0* body = (sTitleMetadataBody_v0*)(serialised_data_.data() + sign_size);
	body->set_issuer(issuer_.c_str(), issuer_.length());
	body->set_format_version(ES_TMD_VER_0);
	body->set_ca_crl_version(ca_crl_version_);
	body->set_signer_crl_version(signer_crl_version_);
	body->set_system_version(system_version_);
	body->set_title_id(title_id_);
	body->set_title_type(title_type_);
	body->set_company_code(company_code_.c_str());
	body->set_access_rights(access_rights_);
	body->set_title_version(title_version_);
	body->set_content_num(content_num_);
	body->set_boot_content_index(boot_content_index_);
	sPlatormReservedRegion platform_reserved;
	platform_reserved.set_public_save_data_size(public_save_data_size_);
	platform_reserved.set_private_save_data_size(private_save_data_size_);
	platform_reserved.set_twl_flag(twl_flag_);
	body->set_platform_reserved_data((const u8*)&platform_reserved, sizeof(sPlatormReservedRegion));
}

void EsTmd::SerialiseWithoutSign_v1(EsCrypto::EsSignType sign_type)
{
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);

	if (content_list_.size() == 0)
	{
		throw ProjectSnakeException(kModuleName, "No content were specified for tmd");
	}

	size_t tmd_size = sign_size + sizeof(sTitleMetadataBody_v1) + sizeof(sInfoRecord) * kInfoRecordNum + sizeof(sContentInfo_v1)* content_list_.size();
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for tmd");
	}

	// hash buffer
	u8 hash[Crypto::kSha256HashLen];

	// serialise content info
	sContentInfo_v1* info_ptr = (sContentInfo_v1*)(serialised_data_.data() + sign_size + sizeof(sTitleMetadataBody_v1) + sizeof(sInfoRecord) * kInfoRecordNum);
	for (size_t i = 0; i < content_num_; i++)
	{
		info_ptr[i].set_id(content_list_[i].id);
		info_ptr[i].set_index(content_list_[i].index);
		info_ptr[i].set_flag(content_list_[i].flags);
		info_ptr[i].set_size(content_list_[i].size);
		if (IsSha1Hash(content_list_[i].flags)) {
			info_ptr[i].set_sha1_hash(content_list_[i].hash);
		}
		else {
			info_ptr[i].set_sha256_hash(content_list_[i].hash);
		}
	}
	Crypto::Sha256((const u8*)info_ptr, sizeof(sContentInfo) * content_list_.size(), hash); // save hash for info record

	// serialise info records
	sInfoRecord* info_record = (sInfoRecord*)(serialised_data_.data() + sign_size + sizeof(sTitleMetadataBody_v1));
	info_record[0].set_offset(0);
	info_record[0].set_num(content_list_.size());
	info_record[0].set_hash(hash);
	Crypto::Sha256((const u8*)info_record, sizeof(sInfoRecord) * kInfoRecordNum, hash); // save hash for body



	// serialise body
	sTitleMetadataBody_v1* body = (sTitleMetadataBody_v1*)(serialised_data_.data() + sign_size);
	body->set_issuer(issuer_.c_str(), issuer_.length());
	body->set_format_version(ES_TMD_VER_1);
	body->set_ca_crl_version(ca_crl_version_);
	body->set_signer_crl_version(signer_crl_version_);
	body->set_system_version(system_version_);
	body->set_title_id(title_id_);
	body->set_title_type(title_type_);
	body->set_company_code(company_code_.c_str());
	body->set_access_rights(access_rights_);
	body->set_title_version(title_version_);
	body->set_content_num(content_num_);
	body->set_boot_content_index(boot_content_index_);
	body->set_info_records_hash(hash);
	sPlatormReservedRegion platform_reserved;
	platform_reserved.set_public_save_data_size(public_save_data_size_);
	platform_reserved.set_private_save_data_size(private_save_data_size_);
	platform_reserved.set_twl_flag(twl_flag_);
	body->set_platform_reserved_data((const u8*)&platform_reserved, sizeof(sPlatormReservedRegion));
}

u8 EsTmd::GetRawBinaryFormatVersion(const u8* raw_tmd_body)
{
	return raw_tmd_body[0x40];
}

void EsTmd::Deserialise_v0(const u8 * tmd_data)
{
	// cache body pointer
	const u8* tmd_body = (const u8*)EsCrypto::GetSignedBinaryBody(tmd_data);
	
	// get tmd body
	const sTitleMetadataBody_v0* body = (const sTitleMetadataBody_v0*)tmd_body;

	// save internal copy of tmd
	size_t tmd_size = EsCrypto::GetSignatureSize(tmd_data) + sizeof(sTitleMetadataBody_v0) + sizeof(sContentInfo) * body->content_num();
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for tmd");
	}
	memcpy(serialised_data_.data(), tmd_data, tmd_size);

	// deserialise body
	issuer_ = std::string(body->issuer(), (strlen(body->issuer()) < kSignatureIssuerLen ? strlen(body->issuer()) : kSignatureIssuerLen));
	format_version_ = body->format_version();
	ca_crl_version_ = body->ca_crl_version();
	signer_crl_version_ = body->signer_crl_version();
	system_version_ = body->system_version();
	title_id_ = body->title_id();
	title_type_ = body->title_type();
	company_code_ = std::string(body->company_code(), kCompanyCodeLen);
	access_rights_ = body->access_rights();
	title_version_ = body->title_version();
	content_num_ = body->content_num();
	boot_content_index_ = body->boot_content_index();
	// deserialise platform reserved
	const sPlatormReservedRegion* platform_reserved = (const sPlatormReservedRegion*)body->platform_reserved_data();
	public_save_data_size_ = platform_reserved->public_save_data_size();
	private_save_data_size_ = platform_reserved->private_save_data_size();
	twl_flag_ = platform_reserved->twl_flag();


	// deserialise content info
	const sContentInfo_v0* content_info = (const sContentInfo_v0*)(tmd_body + sizeof(sTitleMetadataBody_v0));
	for (size_t i = 0; i < body->content_num(); i++)
	{
		sContentInfo info { content_info[i].id(), content_info[i].index(), content_info[i].flag(), content_info[i].size() };
		memcpy(info.hash, content_info[i].hash(), Crypto::kSha1HashLen);

		content_list_.push_back(info);
	}
}

void EsTmd::Deserialise_v1(const u8* tmd_data)
{
	// cache body pointer
	const u8* tmd_body = (const u8*)EsCrypto::GetSignedBinaryBody(tmd_data);

	// get tmd body
	const sTitleMetadataBody_v1* body = (const sTitleMetadataBody_v1*)tmd_body;

	// save internal copy of tmd
	size_t tmd_size = EsCrypto::GetSignatureSize(tmd_data) + sizeof(sTitleMetadataBody_v1) + sizeof(sInfoRecord) * kInfoRecordNum + sizeof(sContentInfo) * body->content_num();
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for tmd");
	}
	memcpy(serialised_data_.data(), tmd_data, tmd_size);


	// do hash checks to validate data isn't corrupt
	u8 hash[Crypto::kSha256HashLen];
	// info record hash check
	sInfoRecord* info_record = (sInfoRecord*)(serialised_data_.data() + EsCrypto::kRsa2048SignLen + sizeof(sTitleMetadataBody_v1));
	Crypto::Sha256((u8*)info_record, sizeof(sInfoRecord) * kInfoRecordNum, hash);
	if (memcmp(hash, body->info_records_hash(), Crypto::kSha256HashLen) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Tmd is corrupt (bad info records)");
	}


	// content info chunk hash check
	sContentInfo_v1* content_info = (sContentInfo_v1*)(serialised_data_.data() + EsCrypto::kRsa2048SignLen + sizeof(sTitleMetadataBody_v1) + sizeof(sInfoRecord) * kInfoRecordNum);
	Crypto::Sha256((u8*)content_info, sizeof(sContentInfo_v1) * info_record[0].num(), hash);
	if (memcmp(hash, info_record[0].hash(), Crypto::kSha256HashLen) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Tmd is corrupt (bad content info)");
	}


	// deserialise body
	issuer_ = std::string(body->issuer(), (strlen(body->issuer()) < kSignatureIssuerLen ? strlen(body->issuer()) : kSignatureIssuerLen ));
	format_version_ = body->format_version();
	ca_crl_version_ = body->ca_crl_version();
	signer_crl_version_ = body->signer_crl_version();
	system_version_ = body->system_version();
	title_id_ = body->title_id();
	title_type_ = body->title_type();
	company_code_ = std::string(body->company_code(), kCompanyCodeLen);
	access_rights_ = body->access_rights();
	title_version_ = body->title_version();
	content_num_ = body->content_num();
	boot_content_index_ = body->boot_content_index();
	// deserialise platform reserved
	const sPlatormReservedRegion* platform_reserved = (const sPlatormReservedRegion*)body->platform_reserved_data();
	public_save_data_size_ = platform_reserved->public_save_data_size();
	private_save_data_size_ = platform_reserved->private_save_data_size();
	twl_flag_ = platform_reserved->twl_flag();

	// deserialise content info
	for (size_t i = 0; i < body->content_num(); i++)
	{
		sContentInfo info;
		info.id = content_info[i].id();
		info.index = content_info[i].index();
		info.flags = content_info[i].flag();
		info.size = content_info[i].size();
		memcpy(info.hash, content_info[i].hash(), Crypto::kSha256HashLen);

		content_list_.push_back(info);
	}
}

bool EsTmd::IsSupportedFormatVersion(u8 version) const
{
	return version == ES_TMD_VER_0 || version == ES_TMD_VER_1;
}

void EsTmd::ClearDeserialisedVariables()
{
	issuer_.clear();
	format_version_ = kFormatVersion;
	ca_crl_version_ = kCaCrlVersion;
	signer_crl_version_ = kSignerCrlVersion;
	system_version_ = 0;
	title_id_ = 0;
	title_type_ = (ESTitleType)0;
	company_code_ = "\0\0";
	public_save_data_size_ = 0;
	private_save_data_size_ = 0;
	twl_flag_ = 0;
	access_rights_ = 0;
	title_version_ = 0;
	content_num_ = 0;
	boot_content_index_ = 0;
	content_list_.clear();
}

void EsTmd::SerialiseTmd(const Crypto::sRsa2048Key& private_key)
{
	SerialiseTmd(private_key, ES_TMD_VER_1);
}

void EsTmd::SerialiseTmd(const Crypto::sRsa2048Key& private_key, ESTmdFormatVersion format)
{
	// sign parameters
	EsCrypto::EsSignType sign_type;
	format_version_ = format;

	// serialise
	if (format_version_ == ES_TMD_VER_0)
	{
		sign_type = EsCrypto::ES_SIGN_RSA2048_SHA1;
		SerialiseWithoutSign_v0(sign_type);
	}
	else if(format_version_ == ES_TMD_VER_1)
	{
		sign_type = EsCrypto::ES_SIGN_RSA2048_SHA256;
		SerialiseWithoutSign_v1(sign_type);
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Unsupported tmd version: " + format);
	}

	// sign header
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	if (EsCrypto::RsaSign(sign_type, hash, private_key.modulus, private_key.priv_exponent, serialised_data_.data()) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to sign tmd");
	}
}

void EsTmd::SerialiseTmd(const Crypto::sRsa4096Key& private_key)
{
	SerialiseTmd(private_key, ES_TMD_VER_1);
}

void EsTmd::SerialiseTmd(const Crypto::sRsa4096Key& private_key, ESTmdFormatVersion format)
{
	// sign parameters
	EsCrypto::EsSignType sign_type;

	// serialise
	if (format == ES_TMD_VER_0)
	{
		sign_type = EsCrypto::ES_SIGN_RSA2048_SHA1;
		SerialiseWithoutSign_v0(sign_type);
	}
	else if (format == ES_TMD_VER_1)
	{
		sign_type = EsCrypto::ES_SIGN_RSA2048_SHA256;
		SerialiseWithoutSign_v1(sign_type);
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Unsupported tmd version: " + format);
	}

	// sign header
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	if (EsCrypto::RsaSign(sign_type, hash, private_key.modulus, private_key.priv_exponent, serialised_data_.data()) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to sign tmd");
	}
}

void EsTmd::SetIssuer(const std::string& issuer)
{
	if (issuer.length() > kSignatureIssuerLen)
	{
		throw ProjectSnakeException(kModuleName, "Issuer length is too large");
	}
	issuer_ = issuer;
}

void EsTmd::SetCaCrlVersion(u8 version)
{
	ca_crl_version_ = version;
}

void EsTmd::SetSignerCrlVersion(u8 version)
{
	signer_crl_version_ = version;
}

void EsTmd::SetSystemVersion(u64 system_version)
{
	system_version_ = system_version;
}

void EsTmd::SetTitleId(u64 title_id)
{
	title_id_ = title_id;
}

void EsTmd::SetTitleType(ESTitleType type)
{
	title_type_ = type;
}

void EsTmd::SetCompanyCode(const std::string& company_code)
{
	if (company_code.length() > kCompanyCodeLen)
	{
		throw ProjectSnakeException(kModuleName, "Company code is too large");
	}
	company_code_ = company_code;
}

void EsTmd::SetCtrSaveSize(u32 size)
{
	public_save_data_size_ = size;
}

void EsTmd::SetTwlSaveSize(u32 public_size, u32 private_size)
{
	public_save_data_size_ = public_size;
	private_save_data_size_ = private_size;
}

void EsTmd::SetTwlFlag(u8 flag)
{
	twl_flag_ = flag;
}

void EsTmd::SetAccessRights(u32 access_rights)
{
	access_rights_ = access_rights;
}

void EsTmd::SetTitleVersion(u16 title_version)
{
	title_version_ = title_version;
}

void EsTmd::SetBootContentIndex(u16 index)
{
	boot_content_index_ = index;
}

void EsTmd::AddContent(u32 id, u16 index, u16 flags, u64 size, u8 hash[Crypto::kSha256HashLen])
{
	sContentInfo info{ id, index, flags, size };
	memcpy(info.hash, hash, flags & ES_CONTENT_TYPE_SHA1_HASH ? Crypto::kSha1HashLen : Crypto::kSha256HashLen);
	content_list_.push_back(info);
	content_num_++;
}

void EsTmd::DeserialiseTmd(const u8* tmd_data)
{
	ClearDeserialisedVariables();

	// cache body ptr
	const u8* tmd_body = (const u8*)EsCrypto::GetSignedBinaryBody(tmd_data);

	// initial es signature header check
	if (tmd_body == nullptr)
	{
		throw ProjectSnakeException(kModuleName, "Tmd is corrupt (bad signature identifier)");
	}
	
	// deserialise tmd based on version
	u8 format_version = GetRawBinaryFormatVersion(tmd_body);
	if (format_version == ES_TMD_VER_0) 
	{
		Deserialise_v0(tmd_data);
	}
	else if (format_version == ES_TMD_VER_1) 
	{
		Deserialise_v1(tmd_data);
	}
	else {
		throw ProjectSnakeException(kModuleName, "Unsupported tmd format version");
	}
}

bool EsTmd::ValidateSignature(const Crypto::sRsa2048Key & key) const
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

bool EsTmd::ValidateSignature(const Crypto::sRsa4096Key & key) const
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

bool EsTmd::ValidateSignature(const EsCert & signer) const
{
	EsCrypto::EsSignType sign_type = EsCrypto::GetSignatureType(serialised_data_.data_const());

	if (signer.GetChildIssuer() != GetIssuer())
	{
		//throw ProjectSnakeException(kModuleName, "Failed to verify tmd using parent certificate: is not parent");
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
		throw ProjectSnakeException(kModuleName, "Failed to verify tmd using parent certificate: ECDSA not implemented");
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Failed to verify tmd using parent certificate: public key / signature type mismatch");
	}

	return is_valid;
}

const std::string & EsTmd::GetIssuer() const
{
	return issuer_;
}

u8 EsTmd::GetFormatVersion() const
{
	return format_version_;
}

u8 EsTmd::GetCaCrlVersion() const
{
	return ca_crl_version_;
}

u8 EsTmd::GetSignerCrlVersion() const
{
	return signer_crl_version_;
}

u64 EsTmd::GetSystemVersion() const
{
	return system_version_;
}

u64 EsTmd::GetTitleId() const
{
	return title_id_;
}

EsTmd::ESTitleType EsTmd::GetTitleType() const
{
	return title_type_;
}

const std::string& EsTmd::GetCompanyCode() const
{
	return company_code_;
}

u32 EsTmd::GetCtrSaveDataSize() const
{
	return public_save_data_size_;
}

u32 EsTmd::GetTwlPublicSaveDataSize() const
{
	return public_save_data_size_;
}

u32 EsTmd::GetTwlPrivateSaveDataSize() const
{
	return private_save_data_size_;
}

u8 EsTmd::GetTwlFlag() const
{
	return twl_flag_;
}

u32 EsTmd::GetAccessRights() const
{
	return access_rights_;
}

u16 EsTmd::GetTitleVersion() const
{
	return title_version_;
}

u16 EsTmd::GetContentNum() const
{
	return content_num_;
}

u16 EsTmd::GetBootContentIndex() const
{
	return boot_content_index_;
}

const std::vector<EsTmd::sContentInfo>& EsTmd::GetContentList() const
{
	return content_list_;
}

bool EsTmd::IsEncrypted(u16 flag)
{
	return (flag & ES_CONTENT_TYPE_ENCRYPTED) == ES_CONTENT_TYPE_ENCRYPTED;
}

bool EsTmd::IsOptional(u16 flag)
{
	return (flag & ES_CONTENT_TYPE_OPTIONAL) == ES_CONTENT_TYPE_OPTIONAL;
}

bool EsTmd::IsSha1Hash(u16 flag)
{
	return (flag & ES_CONTENT_TYPE_SHA1_HASH) == ES_CONTENT_TYPE_SHA1_HASH;
}
