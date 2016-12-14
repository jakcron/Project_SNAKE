#pragma once
#include "es_tmd.h"
#include "es_cert_chain.h"

class ESCdnTmd
{
public:
	ESCdnTmd();
	~ESCdnTmd();

	void DeserialiseTmd(const u8* tmd_data, size_t size);
	bool ValidateSignature();
	bool ValidateSignature(const Crypto::sRsa4096Key& root_key);

	const ESTmd& GetTmd();
	const ESCertChain& GetCerts();
private:
	ESTmd tmd_;
	ESCertChain certs_;
};

