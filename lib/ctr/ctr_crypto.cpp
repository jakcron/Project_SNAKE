#include "ctr_crypto.h"

void CtrCrypto::SetupNcchCtr(uint64_t title_id, NcchSectionType section_type, NcchHeader::FormatVersion format, uint8_t ctr[Crypto::kAesBlockSize])
{
}

void CtrCrypto::KeyGenerator(const uint8_t key_x[Crypto::kAes128KeySize], const uint8_t key_y[Crypto::kAes128KeySize], uint8_t key[Crypto::kAes128KeySize])
{
}
