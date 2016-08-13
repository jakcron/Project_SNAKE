#pragma once
#include <cstdlib>
#include "crypto.h"

class EsCrypto
{
public:
	enum EsSignType
	{
		ES_SIGN_RSA4096_SHA1 = 0x00010000,
		ES_SIGN_RSA2048_SHA1 = 0x00010001,
		ES_SIGN_ECDSA_SHA1 = 0x00010002,
		ES_SIGN_RSA4096_SHA256 = 0x00010003,
		ES_SIGN_RSA2048_SHA256 = 0x00010004,
		ES_SIGN_ECDSA_SHA256 = 0x00010005,
	};

	static const int kSignedStringMaxLen = 0x40;
	static const int kRsa4096SignLen = 0x240;
	static const int kRsa2048SignLen = 0x140;
	static const int kEcdsaSignLen = 0x80;

	static int RsaSign(EsSignType type, const u8* hash, const u8* modulus, const u8* priv_exp, u8* signature);
	static int RsaVerify(const u8* hash, const u8* modulus, const u8* signature);

	static const void* GetSignedBinaryBody(const void* signed_binary);
	static size_t GetSignatureSize(const void* signed_binary);

	static void SetupContentAesIv(u16 index, u8 iv[Crypto::kAesBlockSize]);

	
private:
	static size_t GetSignatureSize(EsSignType type);

	static inline EsSignType get_sign_type(const void* signed_binary) { return (EsSignType)be_word(*(u32*)(signed_binary)); }
	static inline void set_sign_type(EsSignType type, void* pre_signing) { *((u32*)(pre_signing)) = be_word(type); }

};