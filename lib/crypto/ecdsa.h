#pragma once
#include <cstdint>

class Ecdsa
{
public:
	enum HashType
	{
		EC_HASH_SHA1,
		EC_HASH_SHA256,
	};
	static const int kEltSize = 0x1E;
	
	struct sEccPoint
	{
		uint8_t r[kEltSize];
		uint8_t s[kEltSize];
	};

	struct sEccPrivateKey
	{
		uint8_t k[kEltSize];
	};


	static int GenerateSignature();
	static int VerifySignature();

private:
	
	static void elt_copy(uint8_t* d, const uint8_t* a);
	static void elt_zero(uint8_t* d);
	static bool elt_is_zero(const uint8_t* d);

	static void elt_add(uint8_t* d, const uint8_t* a, const uint8_t* b);
	static void elt_mul_x(uint8_t* d, const uint8_t* a);
	static void elt_mul(uint8_t* d, const uint8_t* a, const uint8_t* b);
	static void elt_square_to_wide(uint8_t* d, const uint8_t* a);
	static void wide_reduce(uint8_t* d);
	static void elt_square(uint8_t* d, const uint8_t* a);
	static void itoh_tsujii(uint8_t* d, const uint8_t* a, const uint8_t* b, uint32_t j);
	static void elt_inv(uint8_t* d, const uint8_t* a);
	
	static bool point_is_zero(uint8_t* p);
	static void point_double(uint8_t* r, const uint8_t* p);
	static void point_add(uint8_t* r, const uint8_t* p, const uint8_t* q);
	static void point_mul(uint8_t* r, const uint8_t* p, const uint8_t* q); // p is a bignum

	static int generate_ecdsa(uint8_t* R, uint8_t* S, const uint8_t* k, const uint8_t* hash);
	static int check_ecdsa(const uint8_t* Q, const uint8_t* R, const uint8_t* S, const uint8_t* hash);

	static void ec_priv_to_pub(const uint8_t* k, uint8_t* Q);
};

