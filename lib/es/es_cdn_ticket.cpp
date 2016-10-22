#include "es_cdn_ticket.h"



EsCdnTicket::EsCdnTicket()
{
}


EsCdnTicket::~EsCdnTicket()
{
}

void EsCdnTicket::DeserialiseTicket(const u8 * ticket_data, size_t size)
{
	ticket_.DeserialiseTicket(ticket_data);
	if (size > ticket_.GetSerialisedDataSize()) {
		certs_.DeserialiseCertChain(ticket_data + ticket_.GetSerialisedDataSize(), size - ticket_.GetSerialisedDataSize());
	}
}

bool EsCdnTicket::ValidateSignature()
{
	return certs_.ValidateChainExceptCa() && ticket_.ValidateSignature(certs_[ticket_.GetIssuer()]);
}

bool EsCdnTicket::ValidateSignature(const Crypto::sRsa4096Key & root_key)
{
	return certs_.ValidateChain(root_key) && ticket_.ValidateSignature(certs_[ticket_.GetIssuer()]);
}

const EsTicket & EsCdnTicket::GetTicket()
{
	return ticket_;
}

const EsCertChain & EsCdnTicket::GetCerts()
{
	return certs_;
}
