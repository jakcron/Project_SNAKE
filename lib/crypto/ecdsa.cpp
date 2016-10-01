#include "ecdsa.h"
#include <cstring>

int Ecdsa::VerifySignature()
{

	return 0;
}

void Ecdsa::elt_copy(uint8_t* d, const uint8_t* a)
{
	memcpy(d, a, kEltSize);
}
