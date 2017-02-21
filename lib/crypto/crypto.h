#pragma once
#include <cstdint>
#include <cstring>

class Crypto
{
public:
	static const size_t kSha1HashLen = 20;
	static const size_t kSha256HashLen = 32;
	static const size_t kAes128KeySize = 0x10;
	static const size_t kAesBlockSize = 0x10;
	static const size_t KAesCcmNonceSize = 0xc;
	static const size_t kRsa1024Size = 0x80;
	static const size_t kRsa2048Size = 0x100;
	static const size_t kRsa4096Size = 0x200;
	static const size_t kRsaPublicExponentSize = 4;
	static const size_t kEcdsaSize = 0x3C;
	static const size_t kEcParam240Bit = 0x1E;

	enum HashType
	{
		HASH_SHA1,
		HASH_SHA256
	};

#pragma pack (push, 1)
	struct sAes128Key
	{
		uint8_t key[kAes128KeySize];

		void set(const uint8_t key[kAes128KeySize])
		{
			memcpy(this->key, key, kAes128KeySize);
		}
	};

	struct sAesIvCtr
	{
		uint8_t iv[kAesBlockSize];
	};

	struct sRsa1024Key
	{
		uint8_t modulus[kRsa1024Size];
		uint8_t priv_exponent[kRsa1024Size];
		uint8_t public_exponent[kRsaPublicExponentSize];

		void operator=(const sRsa1024Key& other)
		{
			memcpy(this->modulus, modulus, kRsa1024Size);
			memcpy(this->priv_exponent, priv_exponent, kRsa1024Size);
			memcpy(this->public_exponent, other.public_exponent, kRsaPublicExponentSize);
		}

		bool operator==(const sRsa1024Key& other)
		{
			return memcmp(this->modulus, other.modulus, kRsa1024Size) == 0 && memcmp(this->priv_exponent, other.priv_exponent, kRsa1024Size) == 0 && memcpy(this->public_exponent, other.public_exponent, kRsaPublicExponentSize) == 0;
		}
	};

	struct sRsa2048Key
	{
		uint8_t modulus[kRsa2048Size];
		uint8_t priv_exponent[kRsa2048Size];
		uint8_t public_exponent[kRsaPublicExponentSize];

		void operator=(const sRsa2048Key& other)
		{
			memcpy(this->modulus, other.modulus, kRsa2048Size);
			memcpy(this->priv_exponent, other.priv_exponent, kRsa2048Size);
			memcpy(this->public_exponent, other.public_exponent, kRsaPublicExponentSize);
		}

		bool operator==(const sRsa2048Key& other)
		{
			return memcmp(this->modulus, other.modulus, kRsa2048Size) == 0 && memcmp(this->priv_exponent, other.priv_exponent, kRsa2048Size) == 0 && memcpy(this->public_exponent, other.public_exponent, kRsaPublicExponentSize) == 0;
		}
	};

	struct sRsa4096Key
	{
		uint8_t modulus[kRsa4096Size];
		uint8_t priv_exponent[kRsa4096Size];
		uint8_t public_exponent[kRsaPublicExponentSize];

		void operator=(const sRsa4096Key& other)
		{
			memcpy(this->modulus, other.modulus, kRsa4096Size);
			memcpy(this->priv_exponent, other.priv_exponent, kRsa4096Size);
			memcpy(this->public_exponent, other.public_exponent, kRsaPublicExponentSize);
		}

		bool operator==(const sRsa4096Key& other)
		{
			return memcmp(this->modulus, other.modulus, kRsa4096Size) == 0 && memcmp(this->priv_exponent, other.priv_exponent, kRsa4096Size) == 0 && memcpy(this->public_exponent, other.public_exponent, kRsaPublicExponentSize) == 0;
		}
	};

	struct sEccPoint
	{
		uint8_t r[kEcParam240Bit];
		uint8_t s[kEcParam240Bit];

		void operator=(const sEccPoint& other) 
		{
			memcpy(this->r, other.r, kEcParam240Bit);
			memcpy(this->s, other.s, kEcParam240Bit);
		}

		bool operator==(const sEccPoint& other)
		{
			return memcmp(this->r, other.r, kEcParam240Bit) == 0 && memcmp(this->s, other.s, kEcParam240Bit) == 0;
		}
	};

	struct sEccPrivateKey
	{
		uint8_t k[kEcParam240Bit]; // stub
	};
#pragma pack (pop)

	static void Sha1(const uint8_t* in, uint64_t size, uint8_t hash[kSha1HashLen]);
	static void Sha256(const uint8_t* in, uint64_t size, uint8_t hash[kSha256HashLen]);

	// aes-128
	static void AesCtr(const uint8_t* in, uint64_t size, const uint8_t key[kAes128KeySize], uint8_t ctr[kAesBlockSize], uint8_t* out);
	static void AesIncrementCounter(const uint8_t in[kAesBlockSize], size_t block_num, uint8_t out[kAesBlockSize]);
	
	static void AesCbcDecrypt(const uint8_t* in, uint64_t size, const uint8_t key[kAes128KeySize], uint8_t iv[kAesBlockSize], uint8_t* out);
	static void AesCbcEncrypt(const uint8_t* in, uint64_t size, const uint8_t key[kAes128KeySize], uint8_t iv[kAesBlockSize], uint8_t* out);


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
	static inline uint32_t getbe32(const uint8_t* data) { return data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]; }
	static inline void putbe32(uint8_t* data, uint32_t val) { data[0] = val >> 24; data[1] = val >> 16; data[2] = val >> 8; data[3] = val; }
};