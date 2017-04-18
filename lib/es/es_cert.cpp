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
	return serialised_data_.data();
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

void ESCert::SetSubject(const std::string & subject)
{
	if (subject.length() > kStringMax)
	{
		throw ProjectSnakeException(kModuleName, "Subject length is too large");
	}
	subject_ = subject;
}

void ESCert::SetUniqueId(u32 id)
{
	unique_id_ = id;
}

void ESCert::SetPublicKey(const Crypto::sRsa4096Key& key)
{
	public_key_type_ = RSA_4096;
	public_key_rsa4096_.set_modulus(key.modulus);
	public_key_rsa4096_.set_public_exponent(key.public_exponent);
}

void ESCert::SetPublicKey(const Crypto::sRsa2048Key & key)
{
	public_key_type_ = RSA_2048;
	public_key_rsa2048_.set_modulus(key.modulus);
	public_key_rsa2048_.set_public_exponent(key.public_exponent);
}

void ESCert::SetPublicKey(const Crypto::sEccPoint & key)
{
	public_key_type_ = ECDSA;
	public_key_ecdsa_.set_r(key.r);
	public_key_ecdsa_.set_s(key.s);
}

void ESCert::ClearDeserialisedVariables()
{
	issuer_.clear();
	subject_.clear();
	unique_id_ = 0;
	public_key_type_ = (PublicKeyType)0;
	public_key_rsa4096_.clear();
	public_key_rsa2048_.clear();
	public_key_ecdsa_.clear();
	child_issuer_.clear();
}

void ESCert::CreateChildIssuer()
{
	child_issuer_ = issuer_ + "-" + subject_;
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
	ESCrypto::HashData(type, serialised_data_.data() + sign_size, data_size, hash);
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
	sCertificateBody* cert = (sCertificateBody*)(serialised_data_.data() + sign_size);

	// assure valid public key type
	if (!IsValidPublicKeyType(public_key_type_))
	{
		throw ProjectSnakeException(kModuleName, "Certificate public key type is not supported: " + public_key_type_);
	}

	// serialise body
	cert->set_signature_issuer(issuer_.c_str());
	cert->set_public_key_type(public_key_type_);
	cert->set_subject(subject_.c_str());
	cert->set_unique_id(unique_id_);
	CreateChildIssuer();

	// copy public key into serialised data
	if (public_key_type_ == RSA_4096)
	{
		memcpy(serialised_data_.data() + sign_size + sizeof(sCertificateBody), &public_key_rsa4096_, sizeof(sRsa4096PublicKeyBody));
	}
	else if (public_key_type_ == RSA_2048)
	{
		memcpy(serialised_data_.data() + sign_size + sizeof(sCertificateBody), &public_key_rsa2048_, sizeof(sRsa2048PublicKeyBody));
	}
	else if (public_key_type_ == ECDSA)
	{
		memcpy(serialised_data_.data() + sign_size + sizeof(sCertificateBody), &public_key_ecdsa_, sizeof(sEcdsaPublicKeyBody));
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
	const sCertificateBody* cert_body = (const sCertificateBody*)ESCrypto::GetSignedBinaryBody(cert_data);

	// confirm supported public key type
	public_key_type_ = cert_body->public_key_type();
	if (!IsValidPublicKeyType(public_key_type_))
	{
		throw ProjectSnakeException(kModuleName, "Certificate public key type is not supported: " + public_key_type_);
	}

	// get public key size
	u32 public_key_size = GetPublicKeySize(public_key_type_);

	// save internal copy of certificate
	size_t cert_size = ESCrypto::GetSignatureSize(cert_data) + sizeof(sCertificateBody) + public_key_size;
	if (serialised_data_.alloc(cert_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for certificate");
	}
	memcpy(serialised_data_.data(), cert_data, cert_size);
	cert_body = (const sCertificateBody*)ESCrypto::GetSignedBinaryBody(serialised_data_.data());

	if (cert_body->public_key_type() != public_key_type_)
	{
		throw ProjectSnakeException(kModuleName, "ToCToU Data Corruption");
	}

	// deserialise body
	issuer_ = cert_body->signature_issuer();
	public_key_type_ = cert_body->public_key_type();
	subject_ = cert_body->subject();
	unique_id_ = cert_body->unique_id();
	CreateChildIssuer();
	
	// deserialise public key
	const u8* public_key_pos = serialised_data_.data() + ESCrypto::GetSignatureSize(cert_data) + sizeof(sCertificateBody);
	if (public_key_type_ == RSA_4096)
	{
		memcpy(&public_key_rsa4096_, public_key_pos, sizeof(sRsa4096PublicKeyBody));
	}
	else if (public_key_type_ == RSA_2048)
	{
		memcpy(&public_key_rsa2048_, public_key_pos, sizeof(sRsa2048PublicKeyBody));
	}
	else if (public_key_type_ == ECDSA)
	{
		memcpy(&public_key_ecdsa_, public_key_pos, sizeof(sEcdsaPublicKeyBody));
	}
}

bool ESCert::ValidateSignature(const Crypto::sRsa2048Key& key) const
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

bool ESCert::ValidateSignature(const Crypto::sRsa4096Key & key) const
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


bool ESCert::ValidateSignature(const ESCert& signer) const
{
	ESCrypto::ESSignType sign_type = ESCrypto::GetSignatureType(serialised_data_.data());

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

ESCrypto::ESSignType ESCert::GetSignType() const
{
	if (serialised_data_.size() == 0)
	{
		throw ProjectSnakeException(kModuleName, "Data not yet serialised.");
	}

	return ESCrypto::GetSignatureType(serialised_data_.data());
}

const u8 * ESCert::GetSignature() const
{
	if (serialised_data_.size() == 0)
	{
		throw ProjectSnakeException(kModuleName, "Data not yet serialised.");
	}

	return serialised_data_.data() + sizeof(ESCrypto::ESSignType);
}

size_t ESCert::GetSignatureSize() const
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

const std::string & ESCert::GetIssuer() const
{
	return issuer_;
}

const std::string & ESCert::GetSubject() const
{
	return subject_;
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

	memcpy(key.modulus, public_key_rsa4096_.modulus, Crypto::kRsa4096Size);
	memset(key.priv_exponent, 0, Crypto::kRsa4096Size);
	memcpy(key.public_exponent, public_key_rsa4096_.public_exponent, Crypto::kRsaPublicExponentSize);
}

void ESCert::GetPublicKey(Crypto::sRsa2048Key & key) const
{
	if (public_key_type_ != RSA_2048)
	{
		throw ProjectSnakeException(kModuleName, "Public key inconsistent with public key type");
	}

	memcpy(key.modulus, public_key_rsa2048_.modulus, Crypto::kRsa4096Size);
	memset(key.priv_exponent, 0, Crypto::kRsa4096Size);
	memcpy(key.public_exponent, public_key_rsa2048_.public_exponent, Crypto::kRsaPublicExponentSize);
}

void ESCert::GetPublicKey(Crypto::sEccPoint & key) const
{
	if (public_key_type_ != ECDSA)
	{
		throw ProjectSnakeException(kModuleName, "Public key inconsistent with public key type");
	}

	memcpy(key.r, public_key_ecdsa_.r, Crypto::kEcParam240Bit);
	memcpy(key.s, public_key_ecdsa_.s, Crypto::kEcParam240Bit);
}
