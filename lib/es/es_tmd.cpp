#include "es_tmd.h"
#include "es_crypto.h"


ESTmd::ESTmd()
{
}


ESTmd::~ESTmd()
{
}

void ESTmd::operator=(const ESTmd & other)
{
	DeserialiseTmd(other.GetSerialisedData(), other.GetSerialisedDataSize());
}

const u8* ESTmd::GetSerialisedData() const
{
	return serialised_data_.data();
}

size_t ESTmd::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void ESTmd::HashSerialisedData(ESCrypto::ESSignType sign_type, u8* hash) const
{
	size_t data_size = 0;
	size_t sign_size = ESCrypto::GetSignatureSize(sign_type);
	if (format_version_ == ES_TMD_VER_0) 
	{
		data_size = sizeof(sTitleMetadataBody_v0) + sizeof(sContentInfo_v0) * content_num_;
	}
	else if (format_version_ == ES_TMD_VER_1)
	{
		data_size = sizeof(sTitleMetadataBody_v1);
	}
	else {
		throw ProjectSnakeException(kModuleName, "Unsupported TMD version");
	}

	ESCrypto::HashData(sign_type, serialised_data_.data() + sign_size, data_size, hash);
}

void ESTmd::SerialiseWithoutSign_v0(ESCrypto::ESSignType sign_type)
{
	size_t sign_size = ESCrypto::GetSignatureSize(sign_type);

	if (content_list_.size() == 0)
	{
		throw ProjectSnakeException(kModuleName, "No content were specified for TMD");
	}

	size_t tmd_size = sign_size + sizeof(sTitleMetadataBody_v0) + sizeof(sContentInfo_v0)* content_list_.size();
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for TMD");
	}

	// serialise content info
	sContentInfo_v0* info_ptr = (sContentInfo_v0*)(serialised_data_.data() + sign_size + sizeof(sTitleMetadataBody_v0));
	for (size_t i = 0; i < content_num_; i++)
	{
		info_ptr[i].set_id(content_list_[i].GetContentId());
		info_ptr[i].set_index(content_list_[i].GetContentIndex());
		info_ptr[i].set_flag(content_list_[i].GetFlags());
		info_ptr[i].set_size(content_list_[i].GetSize());
		info_ptr[i].set_hash(content_list_[i].GetHash());
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
	body->set_platform_reserved_data((const u8*)&platform_reserved_data_, kPlatformReservedDataSize);
}

void ESTmd::SerialiseWithoutSign_v1(ESCrypto::ESSignType sign_type)
{
	size_t sign_size = ESCrypto::GetSignatureSize(sign_type);

	if (content_list_.size() == 0)
	{
		throw ProjectSnakeException(kModuleName, "No content were specified for TMD");
	}

	size_t tmd_size = sign_size + sizeof(sTitleMetadataBody_v1) + sizeof(sInfoRecord) * kInfoRecordNum + sizeof(sContentInfo_v1)* content_list_.size();
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for TMD");
	}

	// hash buffer
	u8 hash[Crypto::kSha256HashLen];

	// serialise content info
	sContentInfo_v1* info_ptr = (sContentInfo_v1*)(serialised_data_.data() + sign_size + sizeof(sTitleMetadataBody_v1) + sizeof(sInfoRecord) * kInfoRecordNum);
	for (size_t i = 0; i < content_num_; i++)
	{
		info_ptr[i].set_id(content_list_[i].GetContentId());
		info_ptr[i].set_index(content_list_[i].GetContentIndex());
		info_ptr[i].set_flag(content_list_[i].GetFlags());
		info_ptr[i].set_size(content_list_[i].GetSize());
		if (content_list_[i].IsFlagSet(ESContentInfo::ES_CONTENT_FLAG_SHA1_HASH)) {
			info_ptr[i].set_sha1_hash(content_list_[i].GetHash());
		}
		else {
			info_ptr[i].set_sha256_hash(content_list_[i].GetHash());
		}
	}
	Crypto::Sha256((const u8*)info_ptr, sizeof(sContentInfo_v1) * content_list_.size(), hash); // save hash for info record

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
	body->set_platform_reserved_data((const u8*)&platform_reserved_data_, kPlatformReservedDataSize);
}

u8 ESTmd::GetRawBinaryFormatVersion(const u8* raw_tmd_body)
{
	return raw_tmd_body[0x40];
}

void ESTmd::Deserialise_v0(const u8 * tmd_data, size_t size)
{
	// cache body pointer
	const u8* tmd_body = (const u8*)ESCrypto::GetSignedBinaryBody(tmd_data);
	
	// get tmd body
	const sTitleMetadataBody_v0* body = (const sTitleMetadataBody_v0*)tmd_body;

	// save internal copy of tmd
	size_t tmd_size = ESCrypto::GetSignatureSize(tmd_data) + sizeof(sTitleMetadataBody_v0) + sizeof(sContentInfo_v0) * body->content_num();
	if (tmd_size > size)
	{
		throw ProjectSnakeException(kModuleName, "Tmd is corrupt");
	}
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for TMD");
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
	memcpy(platform_reserved_data_, body->platform_reserved_data(), kPlatformReservedDataSize);

	// deserialise content info
	const sContentInfo_v0* content_info = (const sContentInfo_v0*)(tmd_body + sizeof(sTitleMetadataBody_v0));
	for (size_t i = 0; i < body->content_num(); i++)
	{
		content_list_.push_back(ESContentInfo(content_info[i].id(), content_info[i].index(), content_info[i].flag(), content_info[i].size(), content_info[i].hash(), true));
	}
}

void ESTmd::Deserialise_v1(const u8* tmd_data, size_t size)
{
	// cache body pointer
	const u8* tmd_body = (const u8*)ESCrypto::GetSignedBinaryBody(tmd_data);

	// get tmd body
	const sTitleMetadataBody_v1* body = (const sTitleMetadataBody_v1*)tmd_body;

	// save internal copy of tmd
	size_t tmd_size = ESCrypto::GetSignatureSize(tmd_data) + sizeof(sTitleMetadataBody_v1) + sizeof(sInfoRecord) * kInfoRecordNum + sizeof(sContentInfo_v1) * body->content_num();
	if (tmd_size > size)
	{
		throw ProjectSnakeException(kModuleName, "Tmd is corrupt");
	}
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for TMD");
	}
	memcpy(serialised_data_.data(), tmd_data, tmd_size);


	// do hash checks to validate data isn't corrupt
	u8 hash[Crypto::kSha256HashLen];
	// info record hash check
	sInfoRecord* info_record = (sInfoRecord*)(serialised_data_.data() + ESCrypto::kRsa2048SignLen + sizeof(sTitleMetadataBody_v1));
	Crypto::Sha256((u8*)info_record, sizeof(sInfoRecord) * kInfoRecordNum, hash);
	if (memcmp(hash, body->info_records_hash(), Crypto::kSha256HashLen) != 0)
	{
		throw ProjectSnakeException(kModuleName, "TMD is corrupt (bad info records)");
	}


	// content info chunk hash check
	sContentInfo_v1* content_info = (sContentInfo_v1*)(serialised_data_.data() + ESCrypto::kRsa2048SignLen + sizeof(sTitleMetadataBody_v1) + sizeof(sInfoRecord) * kInfoRecordNum);
	Crypto::Sha256((u8*)content_info, sizeof(sContentInfo_v1) * info_record[0].num(), hash);
	if (memcmp(hash, info_record[0].hash(), Crypto::kSha256HashLen) != 0)
	{
		throw ProjectSnakeException(kModuleName, "TMD is corrupt (bad content info)");
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
	memcpy(platform_reserved_data_, body->platform_reserved_data(), kPlatformReservedDataSize);

	// deserialise content info
	for (size_t i = 0; i < body->content_num(); i++)
	{
		content_list_.push_back(ESContentInfo(content_info[i].id(), content_info[i].index(), content_info[i].flag(), content_info[i].size(), content_info[i].hash()));
	}
}

bool ESTmd::IsSupportedFormatVersion(u8 version) const
{
	return version == ES_TMD_VER_0 || version == ES_TMD_VER_1;
}

void ESTmd::ClearDeserialisedVariables()
{
	issuer_.clear();
	format_version_ = kFormatVersion;
	ca_crl_version_ = kCaCrlVersion;
	signer_crl_version_ = kSignerCrlVersion;
	system_version_ = 0;
	title_id_ = 0;
	title_type_ = (ESTitleType)0;
	company_code_ = "\0\0";
	memset(platform_reserved_data_, 0, kPlatformReservedDataSize);
	access_rights_ = 0;
	title_version_ = 0;
	content_num_ = 0;
	boot_content_index_ = 0;
	content_list_.clear();
}

void ESTmd::SerialiseTmd(const Crypto::sRsa2048Key& private_key)
{
	SerialiseTmd(private_key, kDefaultVersion);
}

void ESTmd::SerialiseTmd(const Crypto::sRsa2048Key& private_key, ESTmdFormatVersion format)
{
	// sign parameters
	ESCrypto::ESSignType sign_type;
	format_version_ = format;

	// serialise
	if (format_version_ == ES_TMD_VER_0)
	{
		sign_type = ESCrypto::ES_SIGN_RSA2048_SHA1;
		SerialiseWithoutSign_v0(sign_type);
	}
	else if(format_version_ == ES_TMD_VER_1)
	{
		sign_type = ESCrypto::ES_SIGN_RSA2048_SHA256;
		SerialiseWithoutSign_v1(sign_type);
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Unsupported TMD version: " + format);
	}

	// sign header
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	if (ESCrypto::GenerateSignature(sign_type, hash, private_key, serialised_data_.data()) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to sign TMD");
	}
}

void ESTmd::SerialiseTmd(const Crypto::sRsa4096Key& private_key)
{
	SerialiseTmd(private_key, kDefaultVersion);
}

void ESTmd::SerialiseTmd(const Crypto::sRsa4096Key& private_key, ESTmdFormatVersion format)
{
	// sign parameters
	ESCrypto::ESSignType sign_type;

	// serialise
	if (format == ES_TMD_VER_0)
	{
		sign_type = ESCrypto::ES_SIGN_RSA2048_SHA1;
		SerialiseWithoutSign_v0(sign_type);
	}
	else if (format == ES_TMD_VER_1)
	{
		sign_type = ESCrypto::ES_SIGN_RSA2048_SHA256;
		SerialiseWithoutSign_v1(sign_type);
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Unsupported TMD version: " + format);
	}

	// sign header
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	if (ESCrypto::GenerateSignature(sign_type, hash, private_key, serialised_data_.data()) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to sign TMD");
	}
}

void ESTmd::SetIssuer(const std::string& issuer)
{
	if (issuer.length() > kSignatureIssuerLen)
	{
		throw ProjectSnakeException(kModuleName, "Issuer length is too large");
	}
	issuer_ = issuer;
}

void ESTmd::SetCaCrlVersion(u8 version)
{
	ca_crl_version_ = version;
}

void ESTmd::SetSignerCrlVersion(u8 version)
{
	signer_crl_version_ = version;
}

void ESTmd::SetSystemVersion(u64 system_version)
{
	system_version_ = system_version;
}

void ESTmd::SetTitleId(u64 title_id)
{
	title_id_ = title_id;
}

void ESTmd::SetTitleType(ESTitleType type)
{
	title_type_ = type;
}

void ESTmd::SetCompanyCode(const std::string& company_code)
{
	if (company_code.length() > kCompanyCodeLen)
	{
		throw ProjectSnakeException(kModuleName, "Company code is too large");
	}
	company_code_ = company_code;
}

void ESTmd::SetPlatformReservedData(const u8 * data, u32 size)
{
	memcpy(platform_reserved_data_, data, size);
}

void ESTmd::SetAccessRights(u32 access_rights)
{
	access_rights_ = access_rights;
}

void ESTmd::SetTitleVersion(u16 title_version)
{
	title_version_ = title_version;
}

void ESTmd::SetBootContentIndex(u16 index)
{
	boot_content_index_ = index;
}

void ESTmd::AddContent(const ESContentInfo& content_info)
{
	content_list_.push_back(ESContentInfo(content_info));
	content_num_++;
}

void ESTmd::DeserialiseTmd(const u8* tmd_data, size_t size)
{
	ClearDeserialisedVariables();

	// cache body ptr
	const u8* tmd_body = (const u8*)ESCrypto::GetSignedBinaryBody(tmd_data);

	// initial es signature header check
	if (tmd_body == nullptr)
	{
		throw ProjectSnakeException(kModuleName, "TMD is corrupt (bad signature identifier)");
	}
	
	// deserialise tmd based on version
	u8 format_version = GetRawBinaryFormatVersion(tmd_body);
	if (format_version == ES_TMD_VER_0) 
	{
		Deserialise_v0(tmd_data, size);
	}
	else if (format_version == ES_TMD_VER_1) 
	{
		Deserialise_v1(tmd_data, size);
	}
	else {
		throw ProjectSnakeException(kModuleName, "Unsupported TMD format version");
	}
}

bool ESTmd::ValidateSignature(const Crypto::sRsa2048Key & key) const
{
	ESCrypto::ESSignType sign_type = ESCrypto::GetSignatureType(serialised_data_.data());
	if (!ESCrypto::IsSignRsa2048(sign_type))
	{
		throw ProjectSnakeException(kModuleName, "Attempted to validate signature with incompatible key");
	}

	// signature check
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	return ESCrypto::VerifySignature(hash, key, serialised_data_.data()) == 0;
}

bool ESTmd::ValidateSignature(const Crypto::sRsa4096Key & key) const
{
	ESCrypto::ESSignType sign_type = ESCrypto::GetSignatureType(serialised_data_.data());
	if (!ESCrypto::IsSignRsa4096(sign_type))
	{
		throw ProjectSnakeException(kModuleName, "Attempted to validate signature with incompatible key");
	}

	// signature check
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	return ESCrypto::VerifySignature(hash, key, serialised_data_.data()) == 0;
}

bool ESTmd::ValidateSignature(const ESCert & signer) const
{
	ESCrypto::ESSignType sign_type = ESCrypto::GetSignatureType(serialised_data_.data());

	if (signer.GetChildIssuer() != GetIssuer())
	{
		//throw ProjectSnakeException(kModuleName, "Failed to verify tmd using parent certificate: is not parent");
		return false;
	}

	bool is_valid = false;
	if (signer.GetPublicKeyType() == ESCert::RSA_2048 && ESCrypto::IsSignRsa2048(sign_type))
	{
		Crypto::sRsa2048Key rsa_key;
		signer.GetPublicKey(rsa_key);
		is_valid = ValidateSignature(rsa_key);
	}
	else if (signer.GetPublicKeyType() == ESCert::RSA_4096 && ESCrypto::IsSignRsa4096(sign_type))
	{
		Crypto::sRsa4096Key rsa_key;
		signer.GetPublicKey(rsa_key);
		is_valid = ValidateSignature(rsa_key);
	}
	else if (signer.GetPublicKeyType() == ESCert::ECDSA && ESCrypto::IsSignEcdsa(sign_type))
	{
		throw ProjectSnakeException(kModuleName, "Failed to verify TMD using parent certificate: ECDSA not implemented");
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Failed to verify TMD using parent certificate: public key / signature type mismatch");
	}

	return is_valid;
}

ESCrypto::ESSignType ESTmd::GetSignType() const
{
	if (serialised_data_.size() == 0)
	{
		throw ProjectSnakeException(kModuleName, "Data not yet serialised.");
	}

	return ESCrypto::GetSignatureType(serialised_data_.data());
}

const u8 * ESTmd::GetSignature() const
{
	if (serialised_data_.size() == 0)
	{
		throw ProjectSnakeException(kModuleName, "Data not yet serialised.");
	}

	return serialised_data_.data() + sizeof(ESCrypto::ESSignType);
}

size_t ESTmd::GetSignatureSize() const
{
	size_t size = 0;
	ESCrypto::ESSignType sign_type = GetSignType();
	if (ESCrypto::IsSignRsa4096(sign_type))
	{
		size = Crypto::kRsa4096Size;
	}
	else if (ESCrypto::IsSignRsa2048(sign_type))
	{
		size = Crypto::kRsa2048Size;
	}
	else if (ESCrypto::IsSignEcdsa(sign_type))
	{
		size = Crypto::kEcdsaSize;
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Illegal ESSignType: " + sign_type);
	}
	return size;
}

const std::string & ESTmd::GetIssuer() const
{
	return issuer_;
}

u8 ESTmd::GetFormatVersion() const
{
	return format_version_;
}

u8 ESTmd::GetCaCrlVersion() const
{
	return ca_crl_version_;
}

u8 ESTmd::GetSignerCrlVersion() const
{
	return signer_crl_version_;
}

u64 ESTmd::GetSystemVersion() const
{
	return system_version_;
}

u64 ESTmd::GetTitleId() const
{
	return title_id_;
}

ESTmd::ESTitleType ESTmd::GetTitleType() const
{
	return title_type_;
}

const std::string& ESTmd::GetCompanyCode() const
{
	return company_code_;
}

bool ESTmd::HasPlatformReservedData() const
{
	bool has_data = false;
	for (size_t i = 0; i < kPlatformReservedDataSize; i++)
	{
		if (platform_reserved_data_[i] != 0)
		{
			has_data = true;
			break;
		}
	}
	return has_data;
}

const u8 * ESTmd::GetPlatformReservedData() const
{
	return platform_reserved_data_;
}

u32 ESTmd::GetAccessRights() const
{
	return access_rights_;
}

u16 ESTmd::GetTitleVersion() const
{
	return title_version_;
}

u16 ESTmd::GetContentNum() const
{
	return content_num_;
}

u16 ESTmd::GetBootContentIndex() const
{
	return boot_content_index_;
}

const std::vector<ESContentInfo>& ESTmd::GetContentList() const
{
	return content_list_;
}