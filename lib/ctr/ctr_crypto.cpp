#include "ctr_crypto.h"

// 128bit wraparound math
inline int32_t wrap_index(int32_t i)
{
	return i < 0 ? ((i % 16) + 16) % 16 : (i > 15 ? i % 16 : i);
}

void CtrCrypto::n128_xor(const u8 *a, const u8 *b, u8 *out)
{
	for (int i = 0; i < 16; i++) {
		out[i] = a[i] ^ b[i];
	}
}

void CtrCrypto::n128_rrot(const u8 *in, u32 rot, u8 *out)
{
	u32 bit_shift, byte_shift;

	rot = rot % 128;
	byte_shift = rot / 8;
	bit_shift = rot % 8;

	for (int32_t i = 0; i < 16; i++)
	{
		out[i] = (in[wrap_index(i - byte_shift)] >> bit_shift) | (in[wrap_index(i - byte_shift - 1)] << (8 - bit_shift));
	}
}

void CtrCrypto::n128_lrot(const u8 *in, u32 rot, u8 *out)
{
	u32 bit_shift, byte_shift;

	rot = rot % 128;
	byte_shift = rot / 8;
	bit_shift = rot % 8;

	for (int32_t i = 0; i < 16; i++)
	{
		out[i] = (in[wrap_index(i + byte_shift)] << bit_shift) | (in[wrap_index(i + byte_shift + 1)] >> (8 - bit_shift));
	}
}

/* out = a + b
*/
void CtrCrypto::n128_add(const u8 *a, const u8 *b, u8 *out)
{
	u8 carry = 0;
	u32 sum = 0;

	for (int i = 15; i >= 0; i--)
	{
		sum = a[i] + b[i] + carry;
		carry = sum >> 8;
		out[i] = sum & 0xff;
	}
}

void CtrCrypto::KeyGenerator(const uint8_t key_x[Crypto::kAes128KeySize], const uint8_t key_y[Crypto::kAes128KeySize], uint8_t key[Crypto::kAes128KeySize])
{
	static const u8 kCtrKeyGenSecret[16] = { 0x1F, 0xF9, 0xE9, 0xAA, 0xC5, 0xFE, 0x04, 0x08, 0x02, 0x45, 0x91, 0xDC, 0x5D, 0x52, 0x76, 0x8A };
	u8 key_x_rot[16], key_xy[16], key_xyc[16];

	// key_x_rot = key_x <<< 2\n
	n128_lrot(key_x, 2, key_x_rot);

	// key_xy = key_x_rot ^ key_y;
	n128_xor(key_x_rot, key_y, key_xy);

	// key_xyc = key_xy + secret;
	n128_add(key_xy, kCtrKeyGenSecret, key_xyc);

	// key_normal = key_xyc >>> 41
	n128_rrot(key_xyc, 41, key);
}
