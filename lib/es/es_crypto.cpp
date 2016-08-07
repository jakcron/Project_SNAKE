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

	switch (type)
	{
	case(ES_SIGN_RSA4096_SHA1) :
	case(ES_SIGN_RSA4096_SHA256) :
	{
		rsa.len = Crypto::kRsa4096Size;
		hash_id = (type == ES_SIGN_RSA4096_SHA1) ? SIG_RSA_SHA1 : SIG_RSA_SHA256;
		hash_len = (type == ES_SIGN_RSA4096_SHA1) ? Crypto::kSha1HashLen : Crypto::kSha256HashLen;
		break;
	}
	case(ES_SIGN_RSA2048_SHA1) :
	case(ES_SIGN_RSA2048_SHA256) :
	{
		rsa.len = Crypto::kRsa2048Size;
		hash_id = (type == ES_SIGN_RSA2048_SHA1) ? SIG_RSA_SHA1 : SIG_RSA_SHA256;
		hash_len = (type == ES_SIGN_RSA2048_SHA1) ? Crypto::kSha1HashLen : Crypto::kSha256HashLen;
		break;
	}
	default:
		return 1;
	}

	mpi_read_binary(&rsa.E, public_exponent, sizeof(public_exponent));
	mpi_read_binary(&rsa.N, modulus, rsa.len);

	ret = rsa_rsassa_pkcs1_v15_verify(&rsa, RSA_PRIVATE, hash_id, hash_len, hash, signature + 4);

	rsa_free(&rsa);

	return ret;
}

const void * EsCrypto::GetSignedBinaryBody(const void * signed_binary)
{
	EsSignType sign_type = get_sign_type(signed_binary);
	size_t signature_size = GetSignatureSize(sign_type);

	if (signature_size == 0) return nullptr;
	
	return ((const u8*)signed_binary) + signature_size;
}

size_t EsCrypto::GetSignatureSize(const void * signed_binary)
{
	return GetSignatureSize(get_sign_type(signed_binary));
}

void EsCrypto::SetupContentAesIv(u16 index, u8 * iv)
{
	memset(iv, 0, Crypto::kAesBlockSize);
	iv[0] = (index >> 8) & 0xff;
	iv[1] = index & 0xff;
}

size_t EsCrypto::GetSignatureSize(EsSignType type)
{
	switch (type)
	{
	case (ES_SIGN_RSA4096_SHA1):
	case (ES_SIGN_RSA4096_SHA256):
		return kRsa4096SignLen;
	case (ES_SIGN_RSA2048_SHA1):
	case (ES_SIGN_RSA2048_SHA256):
		return kRsa2048SignLen;
	case (ES_SIGN_ECDSA_SHA1):
	case (ES_SIGN_ECDSA_SHA256):
		return kEcdsaSignLen;
	default:
		return 0;
	}
	return 0;
}
