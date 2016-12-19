#include <cstdio>
#include <cstring>
#include "es_crypto.h"

int ESCrypto::GenerateSignature(ESSignType type, const uint8_t * hash, const Crypto::sRsa2048Key & private_key, uint8_t * signature)
{
	return RsaSign(type, hash, private_key, signature);
}

int ESCrypto::VerifySignature(const uint8_t * hash, const Crypto::sRsa2048Key & public_key, const uint8_t * signature)
{
	return RsaVerify(hash, public_key, signature);
}

int ESCrypto::GenerateSignature(ESSignType type, const uint8_t * hash, const Crypto::sRsa4096Key & private_key, uint8_t * signature)
{
	return RsaSign(type, hash, private_key, signature);
}

int ESCrypto::VerifySignature(const uint8_t * hash, const Crypto::sRsa4096Key & public_key, const uint8_t * signature)
{
	return RsaVerify(hash, public_key, signature);
}

int ESCrypto::GenerateSignature(ESSignType type, const uint8_t * hash, const Crypto::sEccPrivateKey & private_key, uint8_t * signature)
{
	return 1;
}

int ESCrypto::VerifySignature(const uint8_t * hash, const Crypto::sEccPoint & public_key, const uint8_t * signature)
{
	return 1;
}

int ESCrypto::RsaSign(ESSignType type, const uint8_t * hash, const Crypto::sRsa4096Key & private_key, uint8_t * signature)
{
	if (!IsSignRsa4096(type))
	{
		return 1;
	}
	set_sign_type(type, signature);
	return Crypto::RsaSign(private_key, GetHashType(type), hash, signature + 4);
}

int ESCrypto::RsaSign(ESSignType type, const uint8_t * hash, const Crypto::sRsa2048Key & private_key, uint8_t * signature)
{
	if (!IsSignRsa2048(type))
	{
		return 1;
	}
	set_sign_type(type, signature);
	return Crypto::RsaSign(private_key, GetHashType(type), hash, signature + 4);
}

int ESCrypto::RsaVerify(const uint8_t * hash, const Crypto::sRsa4096Key & public_key, const uint8_t * signature)
{
	if (!IsSignRsa4096(get_sign_type(signature)))
	{
		return 1;
	}
	return Crypto::RsaVerify(public_key, GetHashType(get_sign_type(signature)), hash, signature + 4);
}

int ESCrypto::RsaVerify(const uint8_t * hash, const Crypto::sRsa2048Key & public_key, const uint8_t * signature)
{
	if (!IsSignRsa2048(get_sign_type(signature)))
	{
		return 1;
	}
	return Crypto::RsaVerify(public_key, GetHashType(get_sign_type(signature)), hash, signature + 4);
}

ESCrypto::ESSignType ESCrypto::GetSignatureType(const void* signed_binary)
{
	return get_sign_type(signed_binary);
}

size_t ESCrypto::GetSignatureSize(const void* signed_binary)
{
	if (signed_binary == nullptr)
	{
		return 0;
	}
	return GetSignatureSize(get_sign_type(signed_binary));
}

size_t ESCrypto::GetSignatureSize(ESSignType type)
{
	size_t size = 0;
	switch (type)
	{
	case (ES_SIGN_RSA4096_SHA1):
	case (ES_SIGN_RSA4096_SHA256):
		size = kRsa4096SignLen;
		break;
	case (ES_SIGN_RSA2048_SHA1):
	case (ES_SIGN_RSA2048_SHA256):
		size = kRsa2048SignLen;
		break;
	case (ES_SIGN_ECDSA_SHA1):
	case (ES_SIGN_ECDSA_SHA256):
		size = kEcdsaSignLen;
		break;
	default:
		break;
	}
	return size;
}


const void* ESCrypto::GetSignedBinaryBody(const void* signed_binary)
{
	if (signed_binary == nullptr)
	{
		return nullptr;
	}

	ESSignType sign_type = get_sign_type(signed_binary);
	size_t signature_size = GetSignatureSize(sign_type);

	if (signature_size == 0) return nullptr;
	
	return ((const uint8_t*)signed_binary) + signature_size;
}

bool ESCrypto::IsSignRsa4096(ESSignType type)
{
	return type == ES_SIGN_RSA4096_SHA1 || type == ES_SIGN_RSA4096_SHA256;
}

bool ESCrypto::IsSignRsa2048(ESSignType type)
{
	return type == ES_SIGN_RSA2048_SHA1 || type == ES_SIGN_RSA2048_SHA256;
}

bool ESCrypto::IsSignEcdsa(ESSignType type)
{
	return type == ES_SIGN_ECDSA_SHA1 || type == ES_SIGN_ECDSA_SHA256;
}

bool ESCrypto::IsSignHashSha1(ESSignType type)
{
	return type == ES_SIGN_ECDSA_SHA1 || type == ES_SIGN_RSA2048_SHA1 || type == ES_SIGN_RSA4096_SHA1;
}

bool ESCrypto::IsSignHashSha256(ESSignType type)
{
	return type == ES_SIGN_ECDSA_SHA256 || type == ES_SIGN_RSA2048_SHA256 || type == ES_SIGN_RSA4096_SHA256;
}

void ESCrypto::HashData(ESSignType type, const uint8_t * data, size_t size, uint8_t * hash)
{
	if (ESCrypto::IsSignHashSha1(type))
	{
		Crypto::Sha1(data, size, hash);
	}
	else if (ESCrypto::IsSignHashSha256(type))
	{
		Crypto::Sha256(data, size, hash);
	}
}

void ESCrypto::SetupContentAesIv(uint16_t index, uint8_t iv[Crypto::kAesBlockSize])
{
	memset(iv, 0, Crypto::kAesBlockSize);
	iv[0] = (index >> 8) & 0xff;
	iv[1] = index & 0xff;
}

Crypto::HashType ESCrypto::GetHashType(ESSignType type)
{
	return IsSignHashSha1(type) ? Crypto::HASH_SHA1 : Crypto::HASH_SHA256;
}

