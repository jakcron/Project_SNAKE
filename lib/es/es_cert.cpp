#include "es_cert.h"



ESCert::ESCert() :
	serialised_data_()
{
	ClearDeserialisedVariables();
}


ESCert::~ESCert()
{
	//printf("Kill Cert %s\n", name_.c_str());
}

void ESCert::operator=(const ESCert & other)
{
	DeserialiseCert(other.GetSerialisedData());
}

const u8* ESCert::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t ESCert::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void ESCert::SerialiseCert(const Crypto::sRsa2048Key& private_key)
{
	SerialiseCert(private_key, false);
}

void ESCert::SerialiseCert(const Crypto::sRsa2048Key& private_key, bool use_sha_1)
{
	// sign parameters
	ESCrypto::ESSignType sign_type = use_sha_1 ? ESCrypto::ES_SIGN_RSA2048_SHA1 : ESCrypto::ES_SIGN_RSA2048_SHA256;
	
	// serialise
	SerialiseWithoutSign(sign_type);

	// sign header
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	if (ESCrypto::GenerateSignature(sign_type, hash, private_key, serialised_data_.data()) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to sign certificate");
	}
}

void ESCert::SerialiseCert(const Crypto::sRsa4096Key& private_key)
{
	SerialiseCert(private_key, false);
}

void ESCert::SerialiseCert(const Crypto::sRsa4096Key& private_key, bool use_sha_1)
{
	// sign parameters
	ESCrypto::ESSignType sign_type = use_sha_1 ? ESCrypto::ES_SIGN_RSA4096_SHA1 : ESCrypto::ES_SIGN_RSA4096_SHA256;

	// serialise
	SerialiseWithoutSign(sign_type);

	// sign header
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	if (ESCrypto::GenerateSignature(sign_type, hash, private_key, serialised_data_.data()) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to sign certificate");
	}
}

void ESCert::SetIssuer(const std::string & issuer)
{
	if (issuer.length() > kStringMax)
	{
		throw ProjectSnakeException(kModuleName, "Issuer length is too large");
	}
	issuer_ = issuer;
}

void ESCert::SetName(const std::string & name)
{
	if (name.length() > kStringMax)
	{
		throw ProjectSnakeException(kModuleName, "Name length is too large");
	}
	name_ = name;
}

void ESCert::SetUniqueId(u32 id)
{
	unique_id_ = id;
}

void ESCert::SetPublicKey(const Crypto::sRsa4096Key& key)
{
	public_key_type_ = RSA_4096;
	memcpy(public_key_, key.modulus, Crypto::kRsa4096Size);
}

void ESCert::SetPublicKey(const Crypto::sRsa2048Key & key)
{
	public_key_type_ = RSA_2048;
	memcpy(public_key_, key.modulus, Crypto::kRsa2048Size);
}

void ESCert::SetPublicKey(const Crypto::sEccPoint & key)
{
	public_key_type_ = ECDSA;
	memcpy(public_key_, key.r, 0x1e);
	memcpy(public_key_ + 0x1e, key.s, 0x1e);
}

void ESCert::ClearDeserialisedVariables()
{
	issuer_.clear();
	name_.clear();
	unique_id_ = 0;
	public_key_type_ = (PublicKeyType)0;
	memset(public_key_, 0, kPublicKeyBufferLen);
	child_issuer_.clear();
}

void ESCert::CreateChildIssuer()
{
	child_issuer_ = issuer_ + "-" + name_;
	child_issuer_ = child_issuer_.substr(0, kStringMax); // limit child issuer size
}

bool ESCert::IsValidPublicKeyType(PublicKeyType type) const
{
	return (type == RSA_4096 || type == RSA_2048 || type == ECDSA);
}

u32 ESCert::GetPublicKeySize(PublicKeyType type) const
{
	u32 size = 0;
	switch (type)
	{
	case (RSA_4096):
		size = sizeof(sRsa4096PublicKeyBody);
		break;
	case (RSA_2048):
		size = sizeof(sRsa2048PublicKeyBody);
		break;
	case (ECDSA):
		size = sizeof(sEcdsaPublicKeyBody);
		break;
	default:
		break;
	}

	return size;
}

void ESCert::HashSerialisedData(ESCrypto::ESSignType type, u8* hash) const
{
	size_t data_size = sizeof(sCertificateBody) + GetPublicKeySize(public_key_type_);
	size_t sign_size = ESCrypto::GetSignatureSize(type);
	ESCrypto::HashData(type, serialised_data_.data_const() + sign_size, data_size, hash);
}

void ESCert::SerialiseWithoutSign(ESCrypto::ESSignType sign_type)
{
	size_t sign_size = ESCrypto::GetSignatureSize(sign_type);

	// allocate memory
	size_t cert_size = sign_size + sizeof(sCertificateBody) + GetPublicKeySize(public_key_type_);
	if (serialised_data_.alloc(cert_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for certificate");
	}

	// assure valid public key type
	if (!IsValidPublicKeyType(public_key_type_))
	{
		throw ProjectSnakeException(kModuleName, "Certificate public key type is not supported: " + public_key_type());
	}

	// serialise body
	set_signature_issuer(issuer_.c_str(), issuer_.length());
	set_public_key_type(public_key_type_);
	set_name(name_.c_str(), name_.length());
	set_unique_id(unique_id_);
	CreateChildIssuer();

	// copy body into serialised data
	memcpy(serialised_data_.data() + sign_size, &cert_body_, sizeof(sCertificateBody));

	// copy public key into serialised data
	const u8 public_exponent[Crypto::kRsaPublicExponentSize] = { 0x00, 0x01, 0x00, 0x01 };
	if (public_key_type() == RSA_4096)
	{
		sRsa4096PublicKeyBody* rsa_key = (sRsa4096PublicKeyBody*)(serialised_data_.data() + sign_size + sizeof(sCertificateBody));
		set_rsa_public_key_modulus(*rsa_key, public_key_);
		set_rsa_public_key_public_exponent(*rsa_key, public_exponent);
	}
	else if (public_key_type() == RSA_2048)
	{
		sRsa2048PublicKeyBody* rsa_key = (sRsa2048PublicKeyBody*)(serialised_data_.data() + sign_size + sizeof(sCertificateBody));
		set_rsa_public_key_modulus(*rsa_key, public_key_);
		set_rsa_public_key_public_exponent(*rsa_key, public_exponent);
	}
	else if (public_key_type() == ECDSA)
	{
		sEcdsaPublicKeyBody* ecdsa_key = (sEcdsaPublicKeyBody*)(serialised_data_.data() + sign_size + sizeof(sCertificateBody));
		set_ecdsa_public_key(*ecdsa_key, public_key_);
	}
}

void ESCert::DeserialiseCert(const u8* cert_data)
{
	ClearDeserialisedVariables();

	// initial es signature header check
	if (ESCrypto::GetSignedBinaryBody(cert_data) == nullptr)
	{
		throw ProjectSnakeException(kModuleName, "Certificate is corrupt (bad signature identifier)");
	}

	// cache pointer
	const u8* cert_body = (const u8*)ESCrypto::GetSignedBinaryBody(cert_data);
	
	// copy cert body into staging ground
	memcpy(&cert_body_, cert_body, sizeof(sCertificateBody));

	// confirm supported public key type
	if (!IsValidPublicKeyType(public_key_type()))
	{
		throw ProjectSnakeException(kModuleName, "Certificate public key type is not supported: " + public_key_type());
	}

	// get public key size
	u32 public_key_size = GetPublicKeySize(public_key_type());

	// save internal copy of certificate
	size_t cert_size = ESCrypto::GetSignatureSize(cert_data) + sizeof(sCertificateBody) + public_key_size;
	if (serialised_data_.alloc(cert_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for certificate");
	}
	memcpy(serialised_data_.data(), cert_data, cert_size);

	// deserialise body
	issuer_ = signature_issuer();
	public_key_type_ = public_key_type();
	name_ = name();
	unique_id_ = unique_id();
	CreateChildIssuer();
	
	// deserialise public key
	if (public_key_type() == RSA_4096)
	{
		const sRsa4096PublicKeyBody* rsa_key = (const sRsa4096PublicKeyBody*)(cert_body + sizeof(sCertificateBody));
		memcpy(public_key_, rsa_public_key_modulus(*rsa_key), Crypto::kRsa4096Size);
	}
	else if (public_key_type() == RSA_2048)
	{
		const sRsa2048PublicKeyBody* rsa_key = (const sRsa2048PublicKeyBody*)(cert_body + sizeof(sCertificateBody));
		memcpy(public_key_, rsa_public_key_modulus(*rsa_key), Crypto::kRsa2048Size);
	}
	else if (public_key_type() == ECDSA)
	{
		const sEcdsaPublicKeyBody* ecdsa_key = (const sEcdsaPublicKeyBody*)(cert_body + sizeof(sCertificateBody));
		memcpy(public_key_, ecdsa_public_key(*ecdsa_key), Crypto::kEcdsaSize);
	}
}

bool ESCert::ValidateSignature(const Crypto::sRsa2048Key& key) const
{
	ESCrypto::ESSignType sign_type = ESCrypto::GetSignatureType(serialised_data_.data_const());
	if (!ESCrypto::IsSignRsa2048(sign_type))
	{
		throw ProjectSnakeException(kModuleName, "Attempted to validate signature with incompatible key");
	}

	// signature check
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	return ESCrypto::VerifySignature(hash, key, serialised_data_.data_const()) == 0;
}

bool ESCert::ValidateSignature(const Crypto::sRsa4096Key & key) const
{
	ESCrypto::ESSignType sign_type = ESCrypto::GetSignatureType(serialised_data_.data_const());
	if (!ESCrypto::IsSignRsa4096(sign_type))
	{
		throw ProjectSnakeException(kModuleName, "Attempted to validate signature with incompatible key");
	}

	// signature check
	u8 hash[Crypto::kSha256HashLen];
	HashSerialisedData(sign_type, hash);
	return ESCrypto::VerifySignature(hash, key, serialised_data_.data_const()) == 0;
}


bool ESCert::ValidateSignature(const ESCert& signer) const
{
	ESCrypto::ESSignType sign_type = ESCrypto::GetSignatureType(serialised_data_.data_const());

	if (signer.GetChildIssuer() != GetIssuer())
	{
		//throw ProjectSnakeException(kModuleName, "Failed to verify certificate using parent certificate: is not parent");
		return false;
	}

	bool is_valid = false;
	if (signer.GetPublicKeyType() == RSA_2048 && ESCrypto::IsSignRsa2048(sign_type))
	{
		Crypto::sRsa2048Key rsa_key;
		signer.GetPublicKey(rsa_key);
		is_valid = ValidateSignature(rsa_key);
	}
	else if (signer.GetPublicKeyType() == RSA_4096 && ESCrypto::IsSignRsa4096(sign_type))
	{
		Crypto::sRsa4096Key rsa_key;
		signer.GetPublicKey(rsa_key);
		is_valid = ValidateSignature(rsa_key);
	}
	else if (signer.GetPublicKeyType() == ECDSA && ESCrypto::IsSignEcdsa(sign_type))
	{
		throw ProjectSnakeException(kModuleName, "Failed to verify certificate using parent certificate: ECDSA not implemented");
	}
	else
	{
		throw ProjectSnakeException(kModuleName, "Failed to verify certificate using parent certificate: public key / signature type mismatch");
	}

	return is_valid;
}

const std::string & ESCert::GetIssuer() const
{
	return issuer_;
}

const std::string & ESCert::GetName() const
{
	return name_;
}

const std::string & ESCert::GetChildIssuer() const
{
	return child_issuer_;
}

u32 ESCert::GetUniqueId() const
{
	return unique_id_;
}

ESCert::PublicKeyType ESCert::GetPublicKeyType() const
{
	return public_key_type_;
}

void ESCert::GetPublicKey(Crypto::sRsa4096Key & key) const
{
	if (public_key_type_ != RSA_4096)
	{
		throw ProjectSnakeException(kModuleName, "Public key inconsistent with public key type");
	}

	memcpy(key.modulus, public_key_, Crypto::kRsa4096Size);
}

void ESCert::GetPublicKey(Crypto::sRsa2048Key & key) const
{
	if (public_key_type_ != RSA_2048)
	{
		throw ProjectSnakeException(kModuleName, "Public key inconsistent with public key type");
	}

	memcpy(key.modulus, public_key_, Crypto::kRsa2048Size);
}

void ESCert::GetPublicKey(Crypto::sEccPoint & key) const
{
	if (public_key_type_ != ECDSA)
	{
		throw ProjectSnakeException(kModuleName, "Public key inconsistent with public key type");
	}

	memcpy(key.r, public_key_, 0x1e);
	memcpy(key.s, public_key_ + 0x1e, 0x1e);
}
