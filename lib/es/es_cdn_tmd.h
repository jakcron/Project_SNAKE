#pragma once
#include "es_tmd.h"
#include "es_cert_chain.h"

class EsCdnTmd
{
public:
	EsCdnTmd();
	~EsCdnTmd();

	void DeserialiseTmd(const u8* tmd_data, size_t size);
	bool ValidateSignature();
	bool ValidateSignature(const Crypto::sRsa4096Key& root_key);

	const EsTmd& GetTmd();
	const EsCertChain& GetCerts();
private:
	EsTmd tmd_;
	EsCertChain certs_;
};

