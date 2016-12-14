#pragma once
#include <cstdlib>
#include "crypto.h"

class ESCrypto
{
public:
	enum ESSignType
	{
		ES_SIGN_RSA4096_SHA1 = 0x00010000,
		ES_SIGN_RSA2048_SHA1 = 0x00010001,
		ES_SIGN_ECDSA_SHA1 = 0x00010002,
		ES_SIGN_RSA4096_SHA256 = 0x00010003,
		ES_SIGN_RSA2048_SHA256 = 0x00010004,
		ES_SIGN_ECDSA_SHA256 = 0x00010005,
	};

	static const int kSignedStringMaxLen = 0x40;
	static const size_t kRsa4096SignLen = 0x240;
	static const size_t kRsa2048SignLen = 0x140;
	static const size_t kEcdsaSignLen = 0x80;

	static int GenerateSignature(ESSignType type, const u8* hash, const Crypto::sRsa2048Key& private_key, u8* signature);
	static int VerifySignature(const u8* hash, const Crypto::sRsa2048Key& public_key, const u8* signature);
	static int GenerateSignature(ESSignType type, const u8* hash, const Crypto::sRsa4096Key& private_key, u8* signature);
	static int VerifySignature(const u8* hash, const Crypto::sRsa4096Key& public_key, const u8* signature);
	static int GenerateSignature(ESSignType type, const u8* hash, const Crypto::sEccPrivateKey& private_key, u8* signature);
	static int VerifySignature(const u8* hash, const Crypto::sEccPoint& public_key, const u8* signature);

	static ESSignType GetSignatureType(const void* signed_binary);
	static size_t GetSignatureSize(const void* signed_binary);
	static size_t GetSignatureSize(ESSignType type);
	static const void* GetSignedBinaryBody(const void* signed_binary);

	static bool IsSignRsa4096(ESSignType type);
	static bool IsSignRsa2048(ESSignType type);
	static bool IsSignEcdsa(ESSignType type);
	static bool IsSignHashSha1(ESSignType type);
	static bool IsSignHashSha256(ESSignType type);

	static void HashData(ESSignType type, const u8* data, size_t size, u8* hash);

	static void SetupContentAesIv(u16 index, u8 iv[Crypto::kAesBlockSize]);

	
private:
	static inline ESSignType get_sign_type(const void* signed_binary) { return (ESSignType)be_word(*(u32*)(signed_binary)); }
	static inline void set_sign_type(ESSignType type, void* pre_signing) { *((u32*)(pre_signing)) = be_word(type); }

	static size_t GetApiSignSize(ESSignType type);
	static size_t GetApiHashId(ESSignType type);
	static size_t GetApiHashLen(ESSignType type);

	static int RsaSign(ESSignType type, const u8* hash, const u8* modulus, const u8* priv_exp, u8* signature);
	static int RsaVerify(const u8* hash, const u8* modulus, const u8* signature);
};