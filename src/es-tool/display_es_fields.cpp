#include "display_es_fields.h"
#include <cinttypes>

void DisplayEsFields::DisplayCertFields(const ESCert & cert, SigState signState, bool showSignature, bool fullPublicKey)
{
	printf("[Certificate]\n");
	printf("    Serial Number:\n");
	printf("        %02x:%02x:%02x:%02x\n", \
		(cert.GetUniqueId() >> 24) & 0xff, \
		(cert.GetUniqueId() >> 16) & 0xff, \
		(cert.GetUniqueId() >> 8) & 0xff, \
		(cert.GetUniqueId() >> 0) & 0xff);
	if (signState != SIG_UNCHECKED)
	{
		printf("    Signature Algorithm: %s (0x%x) (%s)\n", GetSignatureTypeStr(cert.GetSignType()), cert.GetSignType(), GetSigStateStr(signState));
	}
	else
	{
		printf("    Signature Algorithm: %s (0x%x)\n", GetSignatureTypeStr(cert.GetSignType()), cert.GetSignType());
	}
	if (showSignature)
	{
		DumpHexData(cert.GetSignature(), cert.GetSignatureSize(), 2, 0x10);
	}
	printf("    Issuer: %s\n", cert.GetIssuer().c_str());
	printf("    Subject: %s\n", cert.GetSubject().c_str());
	printf("    Subject Public Key Info:\n");
	if (cert.GetPublicKeyType() == ESCert::RSA_4096)
	{
		Crypto::sRsa4096Key public_key;
		cert.GetPublicKey(public_key);

		printf("        Public Key Algorithm: rsaEncryption\n");
		printf("        RSA Public Key: (4096 bit)\n");
		printf("            Modulus (4096 bit):\n");
		DumpHexData(public_key.modulus, fullPublicKey? Crypto::kRsa4096Size : 4, 4, 0x10);
		printf("            Exponent: %d (0x%x)\n", be_word(*(u32*)(public_key.public_exponent)), be_word(*(u32*)(public_key.public_exponent)));
	}
	else if (cert.GetPublicKeyType() == ESCert::RSA_2048)
	{
		Crypto::sRsa2048Key public_key;
		cert.GetPublicKey(public_key);

		printf("        Public Key Algorithm: rsaEncryption\n");
		printf("        RSA Public Key: (2048 bit)\n");
		printf("            Modulus (2048 bit):\n");
		DumpHexData(public_key.modulus, fullPublicKey ? Crypto::kRsa2048Size : 4, 4, 0x10);
		printf("            Exponent: %d (0x%x)\n", be_word(*(u32*)(public_key.public_exponent)), be_word(*(u32*)(public_key.public_exponent)));
	}
	else if (cert.GetPublicKeyType() == ESCert::ECDSA)
	{
		Crypto::sEccPoint public_key;
		cert.GetPublicKey(public_key);

		printf("        Public Key Algorithm: Elliptic Curve DSA\n");
		printf("        ECDSA Public Key: (480 bit)\n");
		printf("            R (240 bit):\n");
		DumpHexData(public_key.r, fullPublicKey ? Crypto::kEcParam240Bit : 4, 4, 14);
		printf("            S (240 bit):\n");
		DumpHexData(public_key.s, fullPublicKey ? Crypto::kEcParam240Bit : 4, 4, 14);
	}
}

void DisplayEsFields::DisplayTicketFields(const ESTicket & tik, SigState signState, const u8 escrow_key[Crypto::kAes128KeySize], bool showSignature, bool fullPublicKey)
{
	printf("[eTicket]\n");
	printf("    Version: %d\n", tik.GetFormatVersion());
	if (signState != SIG_UNCHECKED)
	{
		printf("    Signature Algorithm: %s (0x%x) (%s)\n", GetSignatureTypeStr(tik.GetSignType()), tik.GetSignType(), GetSigStateStr(signState));
	}
	else
	{
		printf("    Signature Algorithm: %s (0x%x)\n", GetSignatureTypeStr(tik.GetSignType()), tik.GetSignType());
	}
	if (showSignature)
	{
		DumpHexData(tik.GetSignature(), tik.GetSignatureSize(), 2, 0x10);
	}
	
	printf("    Issuer: %s (CACrl=%d SignerCrl=%d)\n", tik.GetIssuer().c_str(), tik.GetCaCrlVersion(), tik.GetSignerCrlVersion());
	if (tik.HasServerPublicKey())
	{
		printf("    Server Public Key Info: \n");
		printf("        Public Key Algorithm: Elliptic Curve DSA\n");
		printf("        ECDSA Public Key: (480 bit)\n");
		printf("            R (240 bit):\n");
		DumpHexData(tik.GetServerPublicKey().r, fullPublicKey? Crypto::kEcParam240Bit : 4, 4, 15);
		printf("            S (240 bit):\n");
		DumpHexData(tik.GetServerPublicKey().s, fullPublicKey ? Crypto::kEcParam240Bit : 4, 4, 15);
	}
	
	printf("    Title Info:\n");
	printf("        Title ID: 0x%016" PRIx64 "\n", tik.GetTitleId());
	ESVersion ver(tik.GetTitleVersion());
	printf("        Version: %d.%d.%d\n", ver.major(), ver.minor(), ver.build());
	printf("    License Info:\n");
	printf("        Ticket ID: 0x%016" PRIx64 "\n", tik.GetTicketId());
	printf("        License Type: %s\n", GetTicketLicenseTypeStr(tik.GetLicenseType()));
	if (tik.IsTicketAssociatedWithDevice())
	{
		printf("        Device ID: 0x%8x\n", tik.GetDeviceId());
	}
	if (tik.IsTicketAssociatedWithEShopAccount())
	{
		printf("        Account ID: 0x%8x\n", tik.GetEShopAccountId());
	}
	
	if (tik.GetEnabledContentList().size() > 0)
	{
		printf("        Allowed Content Indexes:\n");
		DumpUintVector(tik.GetEnabledContentList(), 3, 20);
	}
	
	if (tik.HasLimits())
	{
		printf("        Limits:\n");
		for (size_t i = 0; i < ESTicket::ES_MAX_LIMIT_TYPE; i++)
		{
			if (tik.IsLimitSet((ESTicket::ESLimitCode)i))
			{
				printf("            %s : %d\n", GetTicketLimitCodeStr((ESTicket::ESLimitCode)i), tik.GetLimit((ESTicket::ESLimitCode)i));
			}
		}
	}
	if (tik.GetFormatVersion() == ESTicket::ES_TIK_VER_0)
	{
		printf("        Access Title ID: 0x%08x (mask: 0x%08x)\n", tik.GetAccessTitleId(), tik.GetAccessTitleIdMask());
		printf("        Audit: 0x%02x\n", tik.GetAudit());
	}
	printf("    Title Key Escrow:\n");
	printf("        Escrow Key ID: %d\n", tik.GetCommonKeyIndex());
	printf("        Escrowed Title Key:\n");
	DumpHexData(tik.GetEncryptedTitleKey(), Crypto::kAes128KeySize, 3, 0x10);
	if (escrow_key != nullptr)
	{
		u8 title_key[Crypto::kAes128KeySize];
		tik.GetTitleKey(escrow_key, title_key);
		printf("        Title Key (AES128):\n");
		DumpHexData(title_key, Crypto::kAes128KeySize, 3, 0x10);
	}
}

void DisplayEsFields::DisplayTmdFields(const ESTmd & tmd, SigState signState, bool showSignature)
{
	printf("[Title Metadata]\n");
	printf("    Version: %d\n", tmd.GetFormatVersion());
	if (signState != SIG_UNCHECKED)
	{
		printf("    Signature Algorithm: %s (0x%x) (%s)\n", GetSignatureTypeStr(tmd.GetSignType()), tmd.GetSignType(), GetSigStateStr(signState));
	}
	else
	{
		printf("    Signature Algorithm: %s (0x%x)\n", GetSignatureTypeStr(tmd.GetSignType()), tmd.GetSignType());
	}
	if (showSignature)
	{
		DumpHexData(tmd.GetSignature(), tmd.GetSignatureSize(), 2, 0x10);
	}

	printf("    Issuer: %s (CACrl=%d SignerCrl=%d)\n", tmd.GetIssuer().c_str(), tmd.GetCaCrlVersion(), tmd.GetSignerCrlVersion());

	printf("    Title Info:\n");
	printf("        Title ID: 0x%016" PRIx64 "\n", tmd.GetTitleId());
	ESVersion ver(tmd.GetTitleVersion());
	printf("        Version: %d.%d.%d\n", ver.major(), ver.minor(), ver.build());
	printf("        Title Type: %s (0x%x)\n", GetTmdTitleTypeStr(tmd.GetTitleType()), tmd.GetTitleType());
	if (tmd.GetSystemVersion() != 0)
	{
		printf("        OS Title ID: 0x%016" PRIx64 "\n", tmd.GetSystemVersion());
	}
	if (tmd.GetCompanyCode().empty() != false && tmd.GetCompanyCode()[0] != '\0')
	{
		printf("        Company Code: %.2s\n", tmd.GetCompanyCode().c_str());
	}
	if (tmd.GetAccessRights() != 0)
	{
		printf("        Access Rights: 0x%08x\n", tmd.GetAccessRights());
	}
	if (tmd.HasPlatformReservedData())
	{
		printf("        Platform Reserved Data:\n");
		DumpHexData(tmd.GetPlatformReservedData(), ESTmd::kPlatformReservedDataSize, 3, 0x10);
	}
	printf("        Content Num: %d\n", tmd.GetContentNum());
	printf("        Boot Content Index: %d\n", tmd.GetBootContentIndex());
	for (size_t i = 0; i < tmd.GetContentList().size(); i++)
	{
		printf("    Content %d:\n", tmd.GetContentList()[i].GetContentIndex());
		printf("        ID: 0x%08x\n", tmd.GetContentList()[i].GetContentId());
		printf("        Flags: 0x%04x", tmd.GetContentList()[i].GetFlags());
		if (tmd.GetContentList()[i].IsFlagSet(ESContentInfo::ES_CONTENT_FLAG_ENCRYPTED))
		{
			printf(" [encrypted]");
		}
		if (tmd.GetFormatVersion() == 0)
		{
			if (tmd.GetContentList()[i].IsFlagSet(ESContentInfo::ES_CONTENT_FLAG_DISC))
			{
				printf(" [disc]");
			}
		}
		else
		{
			if (tmd.GetContentList()[i].IsFlagSet(ESContentInfo::ES_CONTENT_FLAG_HASHED))
			{
				printf(" [.h3 hash]");
			}
		}
		
		if (tmd.GetContentList()[i].IsFlagSet(ESContentInfo::ES_CONTENT_FLAG_CFM))
		{
			printf(" [cfm]");
		}
		/*
		if (tmd.GetContentList()[i].IsFlagSet(ESContentInfo::SHA1_HASH))
		{
			printf(" [sha1 hash]");
		}
		*/
		if (tmd.GetContentList()[i].IsFlagSet(ESContentInfo::ES_CONTENT_FLAG_OPTIONAL))
		{
			printf(" [optional]");
		}
		if (tmd.GetContentList()[i].IsFlagSet(ESContentInfo::ES_CONTENT_FLAG_SHARED))
		{
			printf(" [shared]");
		}
		printf("\n");
		printf("        Size: 0x%" PRIx64 "\n", tmd.GetContentList()[i].GetSize());
		printf("        Hash Algorithm: %s\n", tmd.GetContentList()[i].IsSha1Hash() ? "sha1" : "sha256");
		DumpHexData(tmd.GetContentList()[i].GetHash(), tmd.GetContentList()[i].IsSha1Hash() ? Crypto::kSha1HashLen : Crypto::kSha256HashLen, 3, 0x10);
	}
	
}

const char * DisplayEsFields::GetCertPublicKeyTypeStr(ESCert::PublicKeyType type)
{
	const char* str = nullptr;
	switch (type)
	{
	case (ESCert::RSA_4096):
		str = "rsa4096";
		break;
	case (ESCert::RSA_2048):
		str = "rsa2048";
		break;
	case (ESCert::ECDSA):
		str = "ecdsa";
		break;
	default:
		str = "unknown";
	}
	return str;
}

const char * DisplayEsFields::GetSignatureTypeStr(ESCrypto::ESSignType type)
{
	const char* str = nullptr;
	switch (type)
	{
	case (ESCrypto::ES_SIGN_RSA4096_SHA1):
		str = "sha1-rsa4096";
		break;
	case (ESCrypto::ES_SIGN_RSA2048_SHA1):
		str = "sha1-rsa2048";
		break;
	case (ESCrypto::ES_SIGN_ECDSA_SHA1):
		str = "sha1-ecdsa";
		break;
	case (ESCrypto::ES_SIGN_RSA4096_SHA256):
		str = "sha256-rsa4096";
		break;
	case (ESCrypto::ES_SIGN_RSA2048_SHA256):
		str = "sha256-rsa2048";
		break;
	case (ESCrypto::ES_SIGN_ECDSA_SHA256):
		str = "sha256-ecdsa";
		break;
	default:
		str = "unknown";
	}
	return str;
}

const char * DisplayEsFields::GetTicketLimitCodeStr(ESTicket::ESLimitCode limit_code)
{
	const char* str = nullptr;
	switch (limit_code)
	{
	case(ESTicket::ES_LC_DURATION_TIME): 
		str = "DURATION_TIME";
		break;
	case(ESTicket::ES_LC_ABSOLUTE_TIME):
		str = "ABSOLUTE_TIME";
		break;
	case(ESTicket::ES_LC_NUM_TITLES):
		str = "NUM_TITLES";
		break;
	case(ESTicket::ES_LC_NUM_LAUNCH):
		str = "NUM_LAUNCH";
		break;
	case(ESTicket::ES_LC_ELAPSED_TIME):
		str = "ELAPSED_TIME";
		break;
	default:
		str = "UNKNOWN";
	}
	return str;
}

const char * DisplayEsFields::GetTicketLicenseTypeStr(ESTicket::ESLicenseType license_type)
{
	const char* str = nullptr;
	switch (license_type)
	{
	case(ESTicket::ES_LICENSE_PERMANENT):
		str = "Permanent";
		break;
	case(ESTicket::ES_LICENSE_DEMO):
		str = "Demo";
		break;
	case(ESTicket::ES_LICENSE_TRIAL):
		str = "Trial";
		break;
	case(ESTicket::ES_LICENSE_RENTAL):
		str = "Rental";
		break;
	case(ESTicket::ES_LICENSE_SUBSCRIPTION):
		str = "Subscription";
		break;
	case(ESTicket::ES_LICENSE_SERVICE):
		str = "Service";
		break;
	default:
		str = "Unknown";
	}
	return str;
}

const char * DisplayEsFields::GetTmdTitleTypeStr(ESTmd::ESTitleType title_type)
{
	const char* str = nullptr;
	
	switch (title_type)
	{
	case (ESTmd::ES_TITLE_TYPE_NC_TITLE):
		str = "NC_TITLE";
		break;
	case (ESTmd::ES_TITLE_TYPE_NG_TITLE):
		str = "NG_TITLE";
		break;
	case (ESTmd::ES_TITLE_TYPE_RVL):
		str = "RVL";
		break;
	case (ESTmd::ES_TITLE_TYPE_DATA):
		str = "DATA";
		break;
	case (ESTmd::ES_TITLE_TYPE_CTR):
		str = "CTR";
		break;
	case (ESTmd::ES_TITLE_TYPE_CAFE):
		str = "CAFE";
		break;
	default:
		str = "Unknown";
	}

	return str;
}

const char * DisplayEsFields::GetSigStateStr(SigState state)
{
	const char* str = nullptr;

	switch (state)
	{
	case (SIG_INVALID):
		str = "fail";
		break;
	case (SIG_VALID):
		str = "good";
		break;
	default:
		str = "";
	}

	return str;
}

void DisplayEsFields::DumpHexData(const u8 * data, size_t len, size_t tab_prefix, size_t wraparound_limit)
{
	size_t write_pos = 0;
	WriteTabPrefix(tab_prefix);
	for (size_t i = 0; i < len; i++, write_pos++)
	{
		if (write_pos >= wraparound_limit)
		{
			printf("\n");
			WriteTabPrefix(tab_prefix);
			write_pos = 0;
		}
		
		printf("%02x%s", data[i], (i + 1 >= len) ? "" : ":");
	}
	printf("\n");
}

void DisplayEsFields::DumpUintVector(const std::vector<u16>& list, size_t tab_prefix, size_t wraparound_limit)
{
	size_t len = list.size();
	size_t write_pos = 0;
	WriteTabPrefix(tab_prefix);
	for (size_t i = 0; i < len; i++, write_pos++)
	{
		if (write_pos >= wraparound_limit)
		{
			printf("\n");
			WriteTabPrefix(tab_prefix);
			write_pos = 0;
		}

		printf("%d%s", list[i], (i + 1 >= len) ? "" : ", ");
	}
	printf("\n");
}

void DisplayEsFields::WriteTabPrefix(size_t tab_prefix)
{
	for (size_t j = 0; j < tab_prefix; j++)
	{
		printf("    ");
	}
}
