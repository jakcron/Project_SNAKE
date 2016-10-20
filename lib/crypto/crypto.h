#pragma once
#include "types.h"
#include <cstring>

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

#pragma pack (push, 1)
	struct sAes128Key
	{
		u8 key[kAes128KeySize];

		void set(const u8 key[kAes128KeySize])
		{
			memcpy(this->key, key, kAes128KeySize);
		}
	};

	struct sAesIvCtr
	{
		u8 iv[kAesBlockSize];
	};

	struct sRsa1024Key
	{
		uint8_t modulus[kRsa1024Size];
		uint8_t priv_exponent[kRsa1024Size];

		void set(const u8 modulus[kRsa1024Size], const u8 priv_exponent[kRsa1024Size])
		{
			memcpy(this->modulus, modulus, kRsa1024Size);
			memcpy(this->priv_exponent, priv_exponent, kRsa1024Size);
		}

		void operator=(const sRsa1024Key& other)
		{
			set(other.modulus, other.priv_exponent);
		}

		bool operator==(const sRsa1024Key& other)
		{
			return memcmp(this->modulus, other.modulus, kRsa1024Size) == 0 && memcmp(this->priv_exponent, other.priv_exponent, kRsa1024Size) == 0;
		}
	};

	struct sRsa2048Key
	{
		uint8_t modulus[kRsa2048Size];
		uint8_t priv_exponent[kRsa2048Size];

		void operator=(const sRsa2048Key& other)
		{
			memcpy(this->modulus, other.modulus, kRsa2048Size);
			memcpy(this->priv_exponent, other.priv_exponent, kRsa2048Size);
		}

		bool operator==(const sRsa2048Key& other)
		{
			return memcmp(this->modulus, other.modulus, kRsa2048Size) == 0 && memcmp(this->priv_exponent, other.priv_exponent, kRsa2048Size) == 0;
		}
	};

	struct sRsa4096Key
	{
		uint8_t modulus[kRsa4096Size];
		uint8_t priv_exponent[kRsa4096Size];

		void operator=(const sRsa4096Key& other)
		{
			memcpy(this->modulus, other.modulus, kRsa4096Size);
			memcpy(this->priv_exponent, other.priv_exponent, kRsa4096Size);
		}

		bool operator==(const sRsa4096Key& other)
		{
			return memcmp(this->modulus, other.modulus, kRsa4096Size) == 0 && memcmp(this->priv_exponent, other.priv_exponent, kRsa4096Size) == 0;
		}
	};

	struct sEccPoint
	{
		uint8_t r[0x1e];
		uint8_t s[0x1e];

		void operator=(const sEccPoint& other) 
		{
			memcpy(this->r, other.r, 0x1e);
			memcpy(this->s, other.s, 0x1e);
		}

		bool operator==(const sEccPoint& other)
		{
			return memcmp(this->r, other.r, 0x1e) == 0 && memcmp(this->s, other.s, 0x1e) == 0;
		}
	};

	struct sEccPrivateKey
	{
		uint8_t k[0x1e]; // stub
	};
#pragma pack (pop)

	static void Sha1(const u8* in, u32 size, u8 hash[kSha1HashLen]);
	static void Sha256(const u8* in, u32 size, u8 hash[kSha256HashLen]);

	// aes-128
	static void AesCtr(const u8* in, u32 size, const u8 key[kAes128KeySize], u8 ctr[kAesBlockSize], u8* out);
	static void AesCbcDecrypt(const u8* in, u32 size, const u8 key[kAes128KeySize], u8 iv[kAesBlockSize], u8* out);
	static void AesCbcEncrypt(const u8* in, u32 size, const u8 key[kAes128KeySize], u8 iv[kAesBlockSize], u8* out);

	// rsa1024
	static int RsaSign(const sRsa1024Key& key, HashType hash_type, const uint8_t* hash, uint8_t signature[kRsa1024Size]);
	static int RsaVerify(const sRsa1024Key& key, HashType hash_type, const uint8_t* hash, const uint8_t signature[kRsa1024Size]);
	// rsa2048
	static int RsaSign(const sRsa2048Key& key, HashType hash_type, const uint8_t* hash, uint8_t signature[kRsa2048Size]);
	static int RsaVerify(const sRsa2048Key& key, HashType hash_type, const uint8_t* hash, const uint8_t signature[kRsa2048Size]);
	// rsa4096
	static int RsaSign(const sRsa4096Key& key, HashType hash_type, const uint8_t* hash, uint8_t signature[kRsa4096Size]);
	static int RsaVerify(const sRsa4096Key& key, HashType hash_type, const uint8_t* hash, const uint8_t signature[kRsa4096Size]);
	// ecdsa
	static int EcdsaSign(const sEccPrivateKey& key, HashType hash_type, const uint8_t* hash, sEccPoint& signature);
	static int EcdsaVerify(const sEccPoint& key, HashType hash_type, const uint8_t* hash, const sEccPoint& signature);

private:
	static int GetWrappedHashType(HashType type);
	static uint32_t GetWrappedHashSize(HashType type);
};