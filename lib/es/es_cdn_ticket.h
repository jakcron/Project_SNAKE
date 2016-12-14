#pragma once
#include "es_ticket.h"
#include "es_cert_chain.h"

class ESCdnTicket
{
public:
	ESCdnTicket();
	~ESCdnTicket();

	void DeserialiseTicket(const u8* ticket_data, size_t size);
	bool ValidateSignature();
	bool ValidateSignature(const Crypto::sRsa4096Key& root_key);

	const ESTicket& GetTicket();
	const ESCertChain& GetCerts();
private:
	ESTicket ticket_;
	ESCertChain certs_;
};
