#include "es_cdn_tmd.h"



ESCdnTmd::ESCdnTmd()
{
}


ESCdnTmd::~ESCdnTmd()
{
}

void ESCdnTmd::DeserialiseTmd(const u8 * tmd_data, size_t size)
{
	tmd_.DeserialiseTmd(tmd_data, size);
	if (size > tmd_.GetSerialisedDataSize()) {
		certs_.DeserialiseCertChain(tmd_data + tmd_.GetSerialisedDataSize(), size - tmd_.GetSerialisedDataSize());
	}
}

bool ESCdnTmd::ValidateSignature()
{
	return certs_.ValidateChainExceptCa() && tmd_.ValidateSignature(certs_[tmd_.GetIssuer()]);
}

bool ESCdnTmd::ValidateSignature(const Crypto::sRsa4096Key & root_key)
{
	return certs_.ValidateChain(root_key) && tmd_.ValidateSignature(certs_[tmd_.GetIssuer()]);
}

const ESTmd & ESCdnTmd::GetTmd()
{
	return tmd_;
}

const ESCertChain & ESCdnTmd::GetCerts()
{
	return certs_;
}
