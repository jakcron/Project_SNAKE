#pragma once
#include "types.h"

class Crypto
{
public:
	static const int kSha1HashLen = 20;
	static const int kSha256HashLen = 32;
	static const int kAes128KeySize = 0x10;
	static const int kAesBlockSize = 0x10;
	static const int KAesCcmNonceSize = 0xc;
	static const int kRsa1024Size = 0x80;
	static const int kRsa2048Size = 0x100;
	static const int kRsa4096Size = 0x200;
	static const int kRsaPublicExponentSize = 4;
	static const int kEcdsaSize = 0x3C;

	enum HashType
	{
		HASH_SHA1,
		HASH_SHA256
	};

	struct sAes128Key
	{
		u8 key[kAes128KeySize];
	};

	struct sAesIvCtr
	{
		u8 iv[kAesBlockSize];
	};

	struct sRsa1024Key
	{
		uint8_t modulus[kRsa1024Size];
		uint8_t priv_exponent[kRsa1024Size];
	};

	struct sRsa2048Key
	{
		uint8_t modulus[kRsa2048Size];
		uint8_t priv_exponent[kRsa2048Size];
	};

	struct sRsa4096Key
	{
		uint8_t modulus[kRsa4096Size];
		uint8_t priv_exponent[kRsa4096Size];
	};

	struct sEcdsaKey
	{
		uint8_t key[kEcdsaSize];
	};

	static void Sha1(const u8* in, u32 size, u8 hash[kSha1HashLen]);
	static void Sha256(const u8* in, u32 size, u8 hash[kSha256HashLen]);

	static void AesCtr(const u8* in, u32 size, const u8 key[kAes128KeySize], u8 ctr[kAesBlockSize], u8* out);
	static void AesCbcDecrypt(const u8* in, u32 size, const u8 key[kAes128KeySize], u8 iv[kAesBlockSize], u8* out);
	static void AesCbcEncrypt(const u8* in, u32 size, const u8 key[kAes128KeySize], u8 iv[kAesBlockSize], u8* out);


	static int SignRsa1024(const sRsa1024Key& key, HashType hash_type, const uint8_t* hash, uint8_t signature[kRsa1024Size]);
	static int VerifyRsa1024(const sRsa1024Key& key, HashType hash_type, const uint8_t* hash, const uint8_t signature[kRsa1024Size]);
	static int SignRsa2048(const sRsa2048Key& key, HashType hash_type, const uint8_t* hash, uint8_t signature[kRsa2048Size]);
	static int VerifyRsa2048(const sRsa2048Key& key, HashType hash_type, const uint8_t* hash, const uint8_t signature[kRsa2048Size]);
	static int SignRsa4096(const sRsa4096Key& key, HashType hash_type, const uint8_t* hash, uint8_t signature[kRsa4096Size]);
	static int VerifyRsa4096(const sRsa4096Key& key, HashType hash_type, const uint8_t* hash, const uint8_t signature[kRsa4096Size]);

	static int SignRsa2048Sha256(const u8 modulus[kRsa2048Size], const u8 private_exponent[kRsa2048Size], const u8 hash[kSha256HashLen], u8 signature[kRsa2048Size]);
	static int VerifyRsa2048Sha256(const u8 modulus[kRsa2048Size], const u8 hash[kSha256HashLen], const u8 signature[kRsa2048Size]);

private:
	static int GetWrappedHashType(HashType type);
	static uint32_t GetWrappedHashSize(HashType type);
};