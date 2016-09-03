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
	size_t data_size = sizeof(sTitleMetadataBodyVersion1);
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);
	EsCrypto::HashData(sign_type, serialised_data_.data_const() + sign_size, data_size, hash);
}

void EsTmd::SerialiseWithoutSign(EsCrypto::EsSignType sign_type)
{
	size_t sign_size = EsCrypto::GetSignatureSize(sign_type);

	// initial check until version0 is supported
	if (!IsSupportedFormatVersion(format_version_))
	{
		throw ProjectSnakeException(kModuleName, "Unsupported tmd format version");
	}

	if (content_list_.size() == 0)
	{
		throw ProjectSnakeException(kModuleName, "No content were specified for tmd");
	}

	size_t tmd_size = sign_size + sizeof(sTitleMetadataBodyVersion1) + sizeof(sInfoRecord) * kInfoRecordNum + sizeof(sContentInfo)* content_list_.size();
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for tmd");
	}

	// hash buffer
	u8 hash[Crypto::kSha256HashLen];

	// serialise content info
	sContentInfo* info_ptr = (sContentInfo*)(serialised_data_.data() + sign_size + sizeof(sTitleMetadataBodyVersion1) + sizeof(sInfoRecord) * kInfoRecordNum);
	for (size_t i = 0; i < content_num_; i++)
	{
		set_content_info_id(info_ptr[i], content_list_[i].id);
		set_content_info_index(info_ptr[i], content_list_[i].index);
		set_content_info_flags(info_ptr[i], content_list_[i].flags);
		set_content_info_size(info_ptr[i], content_list_[i].size);
		set_content_info_hash(info_ptr[i], content_list_[i].hash, content_list_[i].flags & ES_CONTENT_TYPE_SHA1_HASH);
	}
	Crypto::Sha256((const u8*)info_ptr, sizeof(sContentInfo) * content_list_.size(), hash); // save hash for info record

	// serialise info records
	sInfoRecord* info_record = (sInfoRecord*)(serialised_data_.data() + sign_size + sizeof(sTitleMetadataBodyVersion1));
	set_info_record_offset(info_record[0], 0);
	set_info_record_num(info_record[0], content_list_.size());
	set_info_record_hash(info_record[0], hash);
	Crypto::Sha256((const u8*)info_record, sizeof(sInfoRecord) * kInfoRecordNum, hash); // save hash for body

	// serialise body
	memset(&tmd_body_, 0, sizeof(sTitleMetadataBodyVersion1));
	set_signature_issuer(issuer_.c_str(), issuer_.length());
	set_format_version(format_version_);
	set_ca_crl_version(ca_crl_version_);
	set_signer_crl_version(signer_crl_version_);
	set_system_version(system_version_);
	set_title_id(title_id_);
	set_title_type(title_type_);
	set_group_id(group_id_);
	set_public_save_data_size(public_save_data_size_);
	set_private_save_data_size(private_save_data_size_);
	set_twl_flag(twl_flag_);
	set_access_rights(access_rights_);
	set_title_version(title_version_);
	set_content_num(content_num_);
	set_boot_content_index(boot_content_index_);
	set_info_records_hash(hash);

	// copy body into serialised data
	memcpy(serialised_data_.data() + sign_size, &tmd_body_, sizeof(sTitleMetadataBodyVersion1));
}

bool EsTmd::IsSupportedFormatVersion(u8 version) const
{
	return version == kFormatVersion;
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
	group_id_ = 0;
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
	SerialiseTmd(private_key, false);
}

void EsTmd::SerialiseTmd(const Crypto::sRsa2048Key& private_key, bool use_sha1)
{
	// sign parameters
	EsCrypto::EsSignType sign_type = use_sha1 ? EsCrypto::ES_SIGN_RSA2048_SHA1 : EsCrypto::ES_SIGN_RSA2048_SHA256;

	// serialise
	SerialiseWithoutSign(sign_type);

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
	SerialiseTmd(private_key, false);
}

void EsTmd::SerialiseTmd(const Crypto::sRsa4096Key& private_key, bool use_sha1)
{
	// sign parameters
	EsCrypto::EsSignType sign_type = use_sha1 ? EsCrypto::ES_SIGN_RSA4096_SHA1 : EsCrypto::ES_SIGN_RSA4096_SHA256;

	// serialise
	SerialiseWithoutSign(sign_type);

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

void EsTmd::SetFormatVersion(u8 version)
{
	format_version_ = version;
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

void EsTmd::SetGroupId(u16 group_id)
{
	group_id_ = group_id;
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

	// initial es signature header check
	if (EsCrypto::GetSignedBinaryBody(tmd_data) == nullptr)
	{
		throw ProjectSnakeException(kModuleName, "Tmd is corrupt (bad signature identifier)");
	}

	// cache pointer
	const u8* tmd_body = (const u8*)EsCrypto::GetSignedBinaryBody(tmd_data);

	// copy tmd body into staging ground
	memcpy(&tmd_body_, tmd_body, sizeof(sTitleMetadataBodyVersion1));

	// confirm supported format version
	if (!IsSupportedFormatVersion(format_version()))
	{
		throw ProjectSnakeException(kModuleName, "Unsupported tmd format version");
	}

	// save internal copy of tmd
	size_t tmd_size = EsCrypto::GetSignatureSize(tmd_data) + sizeof(sTitleMetadataBodyVersion1) + sizeof(sInfoRecord) * kInfoRecordNum + sizeof(sContentInfo) * content_num();
	if (serialised_data_.alloc(tmd_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for tmd");
	}
	memcpy(serialised_data_.data(), tmd_data, tmd_size);


	// do hash checks to validate data isn't corrupt
	u8 hash[Crypto::kSha256HashLen];
	// info record hash check
	sInfoRecord* info_record = (sInfoRecord*)(serialised_data_.data() + EsCrypto::kRsa2048SignLen + sizeof(sTitleMetadataBodyVersion1));
	Crypto::Sha256((u8*)info_record, sizeof(sInfoRecord) * kInfoRecordNum, hash);
	if (memcmp(hash, info_records_hash(), Crypto::kSha256HashLen) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Tmd is corrupt (bad info records)");
	}


	// content info chunk hash check
	sContentInfo* content_info = (sContentInfo*)(serialised_data_.data() + EsCrypto::kRsa2048SignLen + sizeof(sTitleMetadataBodyVersion1) + sizeof(sInfoRecord) * kInfoRecordNum);
	Crypto::Sha256((u8*)content_info, sizeof(sContentInfo) * get_info_record_num(info_record[0]), hash);
	if (memcmp(hash, get_info_record_hash(info_record[0]), Crypto::kSha256HashLen) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Tmd is corrupt (bad content info)");
	}


	// deserialise body
	issuer_ = signature_issuer();
	format_version_ = format_version();
	ca_crl_version_ = ca_crl_version();
	signer_crl_version_ = signer_crl_version();
	system_version_ = system_version();
	title_id_ = title_id();
	title_type_ = title_type();
	group_id_ = group_id();
	public_save_data_size_ = public_save_data_size();
	private_save_data_size_ = private_save_data_size();
	twl_flag_ = twl_flag();
	access_rights_ = access_rights();
	title_version_ = title_version();
	content_num_ = content_num();
	boot_content_index_ = boot_content_index();

	// deserialise content info
	for (size_t i = 0; i < content_num(); i++)
	{
		sContentInfo info;
		info.id = get_content_info_id(content_info[i]);
		info.index = get_content_info_index(content_info[i]);
		info.flags = get_content_info_flags(content_info[i]);
		info.size = get_content_info_size(content_info[i]);
		memcpy(info.hash, get_content_info_hash(content_info[i]), Crypto::kSha256HashLen);

		content_list_.push_back(info);
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

u16 EsTmd::GetGroupId() const
{
	return group_id_;
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
