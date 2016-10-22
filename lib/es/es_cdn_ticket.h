#pragma once
#include "es_ticket.h"
#include "es_cert_chain.h"

class EsCdnTicket
{
public:
	EsCdnTicket();
	~EsCdnTicket();

	void DeserialiseTicket(const u8* ticket_data, size_t size);
	bool ValidateSignature();
	bool ValidateSignature(const Crypto::sRsa4096Key& root_key);

	const EsTicket& GetTicket();
	const EsCertChain& GetCerts();
private:
	EsTicket ticket_;
	EsCertChain certs_;
};

