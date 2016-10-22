#include "es_cdn_tmd.h"



EsCdnTmd::EsCdnTmd()
{
}


EsCdnTmd::~EsCdnTmd()
{
}

void EsCdnTmd::DeserialiseTmd(const u8 * tmd_data, size_t size)
{
	tmd_.DeserialiseTmd(tmd_data);
	if (size > tmd_.GetSerialisedDataSize()) {
		certs_.DeserialiseCertChain(tmd_data + tmd_.GetSerialisedDataSize(), size - tmd_.GetSerialisedDataSize());
	}
}

bool EsCdnTmd::ValidateSignature()
{
	return certs_.ValidateChainExceptCa() && tmd_.ValidateSignature(certs_[tmd_.GetIssuer()]);
}

bool EsCdnTmd::ValidateSignature(const Crypto::sRsa4096Key & root_key)
{
	return certs_.ValidateChain(root_key) && tmd_.ValidateSignature(certs_[tmd_.GetIssuer()]);
}

const EsTmd & EsCdnTmd::GetTmd()
{
	return tmd_;
}

const EsCertChain & EsCdnTmd::GetCerts()
{
	return certs_;
}
