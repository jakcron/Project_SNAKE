#pragma once
#include <es/es_cert.h>
#include <es/es_ticket.h>
#include <es/es_tmd.h>

class DisplayEsFields
{
public:
	enum SigState
	{
		SIG_UNCHECKED,
		SIG_INVALID,
		SIG_VALID,
	};

	static void DisplayCertFields(const ESCert& cert, SigState signState, bool showSignature, bool fullPublicKey);
	static void DisplayTicketFields(const ESTicket& tik, SigState signState, const u8 escrow_key[Crypto::kAes128KeySize], bool showSignature, bool fullPublicKey);
	static void DisplayTmdFields(const ESTmd& tmd, SigState signState, bool showSignature);
private:
	static const char* GetCertPublicKeyTypeStr(ESCert::PublicKeyType type);
	static const char* GetSignatureTypeStr(ESCrypto::ESSignType type);
	static const char* GetTicketLimitCodeStr(ESTicket::ESLimitCode limit_code);
	static const char* GetTicketLicenseTypeStr(ESTicket::ESLicenseType license_type);
	static const char* GetTmdTitleTypeStr(ESTmd::ESTitleType title_type);
	static const char* GetSigStateStr(SigState state);
	static void DumpHexData(const u8* data, size_t len, size_t tab_prefix, size_t wraparound_limit);
	static void DumpUintVector(const std::vector<u16>& list, size_t tab_prefix, size_t wraparound_limit);
	static void WriteTabPrefix(size_t tab_prefix);
};