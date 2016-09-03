#include <cstdio>
#include <cstring>
#include "polarssl/rsa.h"
#include "es_crypto.h"

int EsCrypto::RsaSign(EsSignType type, const u8* hash, const u8* modulus, const u8* priv_exp, u8* signature)
{
	int ret;
	rsa_context rsa;
	int hash_id = 0;
	int hash_len = 0;

	rsa_init(&rsa, RSA_PKCS_V15, hash_id);

	if (hash == NULL || modulus == NULL || priv_exp == NULL || signature == NULL) return 1;


	switch (type)
	{
		case(ES_SIGN_RSA4096_SHA1) :
		case(ES_SIGN_RSA4096_SHA256) :
		{
			rsa.len = Crypto::kRsa4096Size;
			hash_id = (type == ES_SIGN_RSA4096_SHA1) ? SIG_RSA_SHA1 : SIG_RSA_SHA256;
			hash_len = (type == ES_SIGN_RSA4096_SHA1) ? Crypto::kSha1HashLen : Crypto::kSha256HashLen;
			memset(signature, 0, sizeof(kRsa4096SignLen));
			break;
		}
		case(ES_SIGN_RSA2048_SHA1) :
		case(ES_SIGN_RSA2048_SHA256) :
		{
			rsa.len = Crypto::kRsa2048Size;
			hash_id = (type == ES_SIGN_RSA2048_SHA1) ? SIG_RSA_SHA1 : SIG_RSA_SHA256;
			hash_len = (type == ES_SIGN_RSA2048_SHA1) ? Crypto::kSha1HashLen : Crypto::kSha256HashLen;
			memset(signature, 0, sizeof(kRsa2048SignLen));
			break;
		}
		default:
			return 1;
	}

	mpi_read_binary(&rsa.D, priv_exp, rsa.len);
	mpi_read_binary(&rsa.N, modulus, rsa.len);

	// set signature id
	set_sign_type(type, signature);
	ret = rsa_rsassa_pkcs1_v15_sign(&rsa, RSA_PRIVATE, hash_id, hash_len, hash, (signature + 4));
	
	rsa_free(&rsa);

	return ret;
}

int EsCrypto::RsaVerify(const u8* hash, const u8* modulus, const u8* signature)
{
	static const u8 public_exponent[3] = { 0x01, 0x00, 0x01 };

	int ret;
	EsSignType type;
	rsa_context rsa;
	int hash_id = 0;
	int hash_len = 0;

	rsa_init(&rsa, RSA_PKCS_V15, hash_id);

	if (hash == NULL || modulus == NULL || signature == NULL) return 1;

	// get signature type
	type = get_sign_type(signature);
	
	if (!IsSignRsa2048(type) && !IsSignRsa4096(type))
	{
		return 1;
	}

	rsa.len = GetApiSignSize(type);
	hash_id = GetApiHashId(type);
	hash_len = GetApiHashLen(type);

	mpi_read_binary(&rsa.E, public_exponent, sizeof(public_exponent));
	mpi_read_binary(&rsa.N, modulus, rsa.len);

	ret = rsa_rsassa_pkcs1_v15_verify(&rsa, RSA_PUBLIC, hash_id, hash_len, hash, signature + 4);

	rsa_free(&rsa);

	return ret;
}

EsCrypto::EsSignType EsCrypto::GetSignatureType(const void* signed_binary)
{
	return get_sign_type(signed_binary);
}

size_t EsCrypto::GetSignatureSize(const void* signed_binary)
{
	if (signed_binary == nullptr)
	{
		return 0;
	}
	return GetSignatureSize(get_sign_type(signed_binary));
}

size_t EsCrypto::GetSignatureSize(EsSignType type)
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


const void* EsCrypto::GetSignedBinaryBody(const void* signed_binary)
{
	if (signed_binary == nullptr)
	{
		return nullptr;
	}

	EsSignType sign_type = get_sign_type(signed_binary);
	size_t signature_size = GetSignatureSize(sign_type);

	if (signature_size == 0) return nullptr;
	
	return ((const u8*)signed_binary) + signature_size;
}

bool EsCrypto::IsSignRsa4096(EsSignType type)
{
	return type == ES_SIGN_RSA4096_SHA1 || type == ES_SIGN_RSA4096_SHA256;
}

bool EsCrypto::IsSignRsa2048(EsSignType type)
{
	return type == ES_SIGN_RSA2048_SHA1 || type == ES_SIGN_RSA2048_SHA256;
}

bool EsCrypto::IsSignEcdsa(EsSignType type)
{
	return type == ES_SIGN_ECDSA_SHA1 || type == ES_SIGN_ECDSA_SHA256;
}

bool EsCrypto::IsSignHashSha1(EsSignType type)
{
	return type == ES_SIGN_ECDSA_SHA1 || type == ES_SIGN_RSA2048_SHA1 || type == ES_SIGN_RSA4096_SHA1;
}

bool EsCrypto::IsSignHashSha256(EsSignType type)
{
	return type == ES_SIGN_ECDSA_SHA256 || type == ES_SIGN_RSA2048_SHA256 || type == ES_SIGN_RSA4096_SHA256;
}

void EsCrypto::HashData(EsSignType type, const u8 * data, size_t size, u8 * hash)
{
	if (EsCrypto::IsSignHashSha1(type))
	{
		Crypto::Sha1(data, size, hash);
	}
	else if (EsCrypto::IsSignHashSha256(type))
	{
		Crypto::Sha256(data, size, hash);
	}
}



void EsCrypto::SetupContentAesIv(u16 index, u8 iv[Crypto::kAesBlockSize])
{
	memset(iv, 0, Crypto::kAesBlockSize);
	iv[0] = (index >> 8) & 0xff;
	iv[1] = index & 0xff;
}

size_t EsCrypto::GetApiSignSize(EsSignType type)
{
	size_t size = 0;
	switch (type)
	{
	case (ES_SIGN_RSA4096_SHA1):
	case (ES_SIGN_RSA4096_SHA256):
		size = Crypto::kRsa4096Size;
		break;
	case (ES_SIGN_RSA2048_SHA1):
	case (ES_SIGN_RSA2048_SHA256):
		size = Crypto::kRsa2048Size;
		break;
	case (ES_SIGN_ECDSA_SHA1):
	case (ES_SIGN_ECDSA_SHA256):
		size = Crypto::kEcdsaSize;
		break;
	default:
		break;
	}
	return size;
}

size_t EsCrypto::GetApiHashId(EsSignType type)
{
	return IsSignHashSha1(type) ? SIG_RSA_SHA1 : SIG_RSA_SHA256;
}

size_t EsCrypto::GetApiHashLen(EsSignType type)
{
	return IsSignHashSha1(type)? Crypto::kSha1HashLen : Crypto::kSha256HashLen;
}

