#include "user_settings.h"
#include "display_es_fields.h"
#include <iostream>
#include <fnd/memory_blob.h>
#include <fnd/file_io.h>
#include <es/es_cert_chain.h>
#include <es/es_cdn_ticket.h>
#include <es/es_cdn_tmd.h>

void processCertChain(UserSettings& cfg)
{
	MemoryBlob blob;
	ESCert cert;

	// read data
	if (!cfg.getInFilePath().empty())
	{
		ESCertChain cdn_raw;
		ESCertChain certs;

		FileIO::ReadFile(cfg.getInFilePath(), blob);

		// deserialise certificate
		cdn_raw.DeserialiseCertChain(blob.data(), blob.size());

		// save certs[0]
		cert = cdn_raw[0];

		// print data
		if (cfg.doPrintData())
		{
			// if appended certificates and are to be used
			DisplayEsFields::SigState sign_state;
			if (certs.GetCerts().GetCertificateNum() > 0 && cfg.doUseCdnCertToVerify())
			{
				// initialise auxilary certs using the cdn_raw, excluding cdn_raw[0] which is the subject of this function
				for (size_t i = 1; i < cdn_raw.GetCertificateNum(); i++)
				{
					certs.AddCertificate(cdn_raw[i]);
				}
			}
			// if requested use externel certificates
			else if (cfg.doUseExternalCertToVerify())
			{
				FileIO::ReadFile(cfg.getExternalCertPath(), blob);
				certs.DeserialiseCertChain(blob.data(), blob.size());
			}

			// validate signature
			try {
				sign_state = cert.ValidateSignature(certs[cert.GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
			}
			catch (const ProjectSnakeException& e) {
				sign_state = DisplayEsFields::SIG_UNCHECKED;
			}

			// show cert fields
			DisplayEsFields::DisplayCertFields(cert, sign_state, cfg.doShowSignatures(), cfg.doShowFullPublicKeys());


			// show cdn certs
			if (certs.GetCertificateNum() > 0 && cfg.doShowCerts())
			{
				for (size_t i = 0; i < certs.GetCertificates().size(); i++)
				{
					DisplayEsFields::DisplayCertFields(certs.GetCertificates()[i], DisplayEsFields::SIG_UNCHECKED, cfg.doShowSignatures(), cfg.doShowFullPublicKeys());
				}
			}
		}
	}
}

void processTicket(UserSettings& cfg)
{
	MemoryBlob blob;
	UserSettings template;

	// read data
	if (!cfg.getInFilePath().empty())
	{
		ESCdnTicket cdn_raw;
		ESCertChain certs;
		ESTicket tik;

		// open file
		FileIO::ReadFile(cfg.getInFilePath(), blob);

		// deserialise ticket/certs
		cdn_raw.DeserialiseTicket(blob.data(), blob.size());

		// copy ticket data to file
		tik = cdn_raw.GetTicket();

		// print info
		if (cfg.doPrintData())
		{
			// if appended certificates and are to be used
			DisplayEsFields::SigState sign_state;
			if (cdn_raw.GetCerts().GetCertificateNum() > 0 && cfg.doUseCdnCertToVerify())
			{
				certs = cdn_raw.GetCerts();
			}
			// if requested use externel certificates
			else if (cfg.doUseExternalCertToVerify())
			{
				FileIO::ReadFile(cfg.getExternalCertPath(), blob);
				certs.DeserialiseCertChain(blob.data(), blob.size());
			}

			// validate signature
			try {
				sign_state = tik.ValidateSignature(certs[tik.GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
			}
			catch (const ProjectSnakeException& e) {
				sign_state = DisplayEsFields::SIG_UNCHECKED;
			}

			// show ticket fields
			DisplayEsFields::DisplayTicketFields(tik, sign_state, nullptr, cfg.doShowSignatures(), cfg.doShowFullPublicKeys());

			// show cdn certs
			if (certs.GetCertificateNum() > 0 && cfg.doShowCerts())
			{
				for (size_t i = 0; i < certs.GetCertificates().size(); i++)
				{
					DisplayEsFields::DisplayCertFields(certs.GetCertificates()[i], DisplayEsFields::SIG_UNCHECKED, cfg.doShowSignatures(), cfg.doShowFullPublicKeys());
				}
			}
		}

		// save tik details to template
		template.setFormatVersion(tik.GetFormatVersion());
		template.setTitleId(tik.GetTitleId());
		template.setVersion(tik.GetTitleVersion());
		template.setCaCrlVersion(tik.GetCaCrlVersion());
		template.setSignerCrlVersion(tik.GetSignerCrlVersion());
		template.setTicketId(tik.GetTicketId());
		template.setEscrowedTitleKey(tik.GetEncryptedTitleKey());
		template.setEscrowKeyId(tik.GetCommonKeyIndex());
		if (tik.IsTicketAssociatedWithDevice())
		{
			template.setDeviceId(tik.GetDeviceId());
		}
		template.setSystemAccessibleContentList(tik.GetSystemAccessibleContentList());
		template.setAccessTitleId(tik.GetAccessTitleId());
		template.setAccessTitleIdMask(tik.GetAccessTitleIdMask());
		template.setLicenseType(tik.GetLicenseType());
		if (tik.IsTicketAssociatedWithEShopAccount())
		{
			template.setEShopAccountId(tik.GetEShopAccountId());
		}
		template.setAudit(tik.GetAudit());
		if (tik.HasLimits())
		{
			std::vector<sESLimit> limits;
			for (size_t i = 0; i < ESTicket::ES_MAX_LIMIT_TYPE; i++)
			{
				ESTicket::ESLimitCode key = (ESTicket::ESLimitCode)i;
				if (tik.IsLimitSet(key))
				{
					limits.push_back({key, tik.GetLimit(key)});
				}
			}
			template.setLimits(limits);
		}
	}

	if (cfg.GetOutFilePath().empty() == false)
	{
		ESTicket tik;

		

		tik.SetCaCrlVersion(0);
		//tik.SetIssuer();
		//tik.SetServerPublicKey();
		if (cfg.getCaCrlVersion().is_set())
		{
			tik.
		}
		else if (template.)
		if (cfg.GetInFilePath().empty() == false)
		{
			new_tmd = cdn_raw.GetTmd();
		}
		else
		{
			if (cfg)
		}
	}
	// create data
	// for each param
	//		tik.param = template.param
	//		tik.param = set.param
	//		if tik.param not set throw exception

}

void processTmd(UserSettings& cfg)
{
	MemoryBlob blob;
	ESTmd tmd;

	// read data
	if (!cfg.getInFilePath().empty())
	{
		ESCdnTmd cdn_raw;
		ESCertChain certs;

		// open file
		FileIO::ReadFile(cfg.getInFilePath(), blob);

		// deserialise tmd
		cdn_raw.DeserialiseTmd(blob.data(), blob.size());

		// copy tmd data to file
		tmd = cdn_raw.GetTmd();

		// print data
		if (cfg.doPrintData())
		{
			// if appended certificates and are to be used
			DisplayEsFields::SigState sign_state;
			if (cdn_raw.GetCerts().GetCertificateNum() > 0 && cfg.doUseCdnCertToVerify())
			{
				certs = cdn_raw.GetCerts();
			}
			// if requested use externel certificates
			else if (cfg.doUseExternalCertToVerify())
			{
				FileIO::ReadFile(cfg.getExternalCertPath(), blob);
				certs.DeserialiseCertChain(blob.data(), blob.size());
			}

			// validate signature
			try {
				sign_state = tmd.ValidateSignature(certs[tmd.GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
			}
			catch (const ProjectSnakeException& e) {
				sign_state = DisplayEsFields::SIG_UNCHECKED;
			}

			// show ticket fields
			DisplayEsFields::DisplayTmdFields(tmd, sign_state, nullptr, cfg.doShowSignatures(), cfg.doShowFullPublicKeys());

			// show cdn certs
			if (certs.GetCertificateNum() > 0 && cfg.doShowCerts())
			{
				for (size_t i = 0; i < certs.GetCertificates().size(); i++)
				{
					DisplayEsFields::DisplayCertFields(certs.GetCertificates()[i], DisplayEsFields::SIG_UNCHECKED, cfg.doShowSignatures(), cfg.doShowFullPublicKeys());
				}
			}
		}
	}
	
	// create data
	/*
	if (cfg.GetOutFilePath().empty() == false)
	{
		ESTmd new_tmd;
		if (cfg.GetInFilePath().empty() == false)
		{
			new_tmd = cdn_raw.GetTmd();
		}
		else
		{
			if (cfg)
		}
	}
	*/

	/*
	algo:

	using existing file as base?
	-> edit data if cfg, reclaim format version too
	-> create new, prompting for input when not provided
	*/

	/*
	new_tmd = tmd.GetTmd();
	ESTmd::ESTmdFormatVersion formatVersion;
	
	// determine format version
	if (cfg.IsFormatVersionSet())
	{
		formatVersion = (ESTmd::ESTmdFormatVersion)cfg.GetFormatVersion();
		switch (formatVersion)
		{
		case (ESTmd::ES_TMD_VER_0):
		case (ESTmd::ES_TMD_VER_1):
			break;
		default:
			throw ProjectSnakeException("ES-TOOL", "Invalid TMD format version: " + cfg.GetFormatVersion());
		}
	}
	else
	{
		formatVersion = ESTmd::ES_TMD_VER_1;
	}

	if (cfg.IsTitleIdSet())
	{
		new_tmd.SetTitleId(cfg.GetTitleId());
	}
	else if (new_tmd.GetTitleId() == 0)
	{
		throw ProjectSnakeException("ES-TOOL", "--titleid not cfg");
	}

	if (cfg.IsVersionSet())
	{
		new_tmd.SetTitleVersion(cfg.GetVersion());
	}

	Crypto::sRsa2048Key key;
	new_tmd.SerialiseTmd(key, formatVersion);
	*/
}

int main(int argc, char** argv)
{
	try {
		UserSettings cfg(argc, argv);

		switch (cfg.getFileType())
		{
			case (cfg.FILE_CERTS) :
				processCertChain(cfg);
				break;
			case (cfg.FILE_TIK) :
				processTicket(cfg);
				break;
			case (cfg.FILE_TMD) :
				processTmd(cfg);
				break;
			default:
				throw ProjectSnakeException("MAIN", "Unknown file type");
		}
	}
	catch (const ProjectSnakeException& e) {
		std::cout << "[" << e.module() << " ERROR] " << e.what() << std::endl;
		return 1;
	}
	return 0;
}