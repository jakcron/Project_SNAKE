#pragma once
#include <fnd/types.h>
#include <crypto/crypto.h>

class CtrCrypto
{
public:
	static void KeyGenerator(const uint8_t key_x[Crypto::kAes128KeySize], const uint8_t key_y[Crypto::kAes128KeySize], uint8_t key[Crypto::kAes128KeySize]);

private:
	static void n128_xor(const u8 *a, const u8 *b, u8 *out);
	static void n128_rrot(const u8 *in, u32 rot, u8 *out);
	static void n128_lrot(const u8 *in, u32 rot, u8 *out);
	static void n128_add(const u8 *a, const u8 *b, u8 *out);
};

