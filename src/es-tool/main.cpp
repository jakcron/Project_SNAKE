#include "user_settings.h"
#include "display_es_fields.h"
#include <iostream>
#include <fstream>
#include <fnd/memory_blob.h>
#include <fnd/file_io.h>
#include <es/es_cert_chain.h>
#include <es/es_cdn_ticket.h>
#include <es/es_cdn_tmd.h>

template <class T>
inline const UserSettings::SettableObject<T>& resolveConflict(const UserSettings::SettableObject<T>& prefered, const UserSettings::SettableObject<T>& fallback)
{
	return prefered.is_set() ? prefered : fallback;
}

template <class T>
inline const UserSettings::SettableObject<T>& resolveConflict(const UserSettings::SettableObject<T>& prefered, const UserSettings::SettableObject<T>& second_choice, const UserSettings::SettableObject<T>& fallback)
{
	return resolveConflict(prefered, resolveConflict(second_choice, fallback));
}


void setUserDefaults(UserSettings& cfg)
{
	cfg.setFormatVersion(1);
	cfg.setCaCrlVersion(0);
	cfg.setSignerCrlVersion(0);
	cfg.setTitleVersion(0);
	cfg.setDeviceId(0);
	cfg.setSystemAccessibleContentList(std::vector<u16>());
	cfg.setAccessTitleId(0);
	cfg.setAccessTitleIdMask(0);
	cfg.setLicenseType(ESTicket::ES_LICENSE_PERMANENT);
	cfg.setEShopAccountId(0);
	cfg.setAudit(0);
	cfg.setLimits(std::vector<UserSettings::sESLimit>());
	cfg.setAccessibleContentList(std::vector<u16>());
}

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
			if (certs.GetCertificateNum() > 0 && cfg.doUseCdnCertToVerify())
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
	UserSettings tikcfg;

	UserSettings defaults;
	setUserDefaults(defaults);

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
				// TODO: move this to a "operator=()" in ESCertChain
				certs.DeserialiseCertChain(cdn_raw.GetCerts().GetSerialisedData(), cdn_raw.GetCerts().GetSerialisedDataSize());
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

		// save tik details to tikcfg
		tikcfg.setIssuer(tik.GetIssuer());
		tikcfg.setServerPublicKey(tik.GetServerPublicKey());
		tikcfg.setFormatVersion(tik.GetFormatVersion());
		tikcfg.setTitleId(tik.GetTitleId());
		tikcfg.setTitleVersion(tik.GetTitleVersion());
		tikcfg.setCaCrlVersion(tik.GetCaCrlVersion());
		tikcfg.setSignerCrlVersion(tik.GetSignerCrlVersion());
		tikcfg.setTicketId(tik.GetTicketId());
		tikcfg.setEscrowedTitleKey(tik.GetEncryptedTitleKey());
		tikcfg.setEscrowKeyId(tik.GetCommonKeyIndex());
		if (tik.IsTicketAssociatedWithDevice())
		{
			tikcfg.setDeviceId(tik.GetDeviceId());
		}
		tikcfg.setSystemAccessibleContentList(tik.GetSystemAccessibleContentList());
		tikcfg.setAccessTitleId(tik.GetAccessTitleId());
		tikcfg.setAccessTitleIdMask(tik.GetAccessTitleIdMask());
		tikcfg.setLicenseType(tik.GetLicenseType());
		if (tik.IsTicketAssociatedWithEShopAccount())
		{
			tikcfg.setEShopAccountId(tik.GetEShopAccountId());
		}
		tikcfg.setAudit(tik.GetAudit());
		if (tik.HasLimits())
		{
			std::vector<UserSettings::sESLimit> limits;
			for (size_t i = 0; i < ESTicket::ES_MAX_LIMIT_TYPE; i++)
			{
				ESTicket::ESLimitCode key = (ESTicket::ESLimitCode)i;
				if (tik.IsLimitSet(key))
				{
					limits.push_back({key, tik.GetLimit(key)});
				}
			}
			tikcfg.setLimits(limits);
		}
		tikcfg.setAccessibleContentList(tik.GetEnabledContentList());

	}

	if (cfg.getOutFilePath().empty() == false)
	{
		ESTicket tik;

#define RESOLVE_SOURCE(method) (resolveConflict(cfg.method(), tikcfg.method(), defaults.method()))

		/* Set data in ticket */
		tik.SetIssuer(RESOLVE_SOURCE(getIssuer).get());
		tik.SetServerPublicKey(RESOLVE_SOURCE(getServerPublicKey).get());
		tik.SetCaCrlVersion(RESOLVE_SOURCE(getCaCrlVersion).get());
		tik.SetSignerCrlVersion(RESOLVE_SOURCE(getSignerCrlVersion).get());
		// if title key and escrow key specified
		if (cfg.getTitleKey().is_set() && cfg.getEscrowKey().is_set())
		{
			tik.SetTitleKey(cfg.getTitleKey().get().data(), cfg.getEscrowKey().get().data());
			tik.SetCommonKeyIndex(cfg.getEscrowKeyId().get());
		}
		// otherwise recycle escrowed title key
		else
		{
			// (provided the title ids are the same)
			if (tikcfg.getTitleId().is_set() && cfg.getTitleId().is_set() && tikcfg.getTitleId().get() != cfg.getTitleId().get())
			{
				throw ProjectSnakeException("ES-TOOL", "Reusing an escrowed titlekey does not permit a change of titleid");
			}

			tik.SetEncryptedTitleKey(resolveConflict(tikcfg.getEscrowedTitleKey(), cfg.getEscrowedTitleKey()).get().data());
			tik.SetCommonKeyIndex(resolveConflict(tikcfg.getEscrowKeyId(), cfg.getEscrowKeyId()).get());
		}

		tik.SetTicketId(RESOLVE_SOURCE(getTicketId).get());
		tik.SetDeviceId(RESOLVE_SOURCE(getDeviceId).get());
		tik.SetTitleId(RESOLVE_SOURCE(getTitleId).get());
		
		// system accessible content
		const std::vector<u16>& system_accessible_content = RESOLVE_SOURCE(getSystemAccessibleContentList).get();
		for (size_t i = 0; i < system_accessible_content.size(); i++)
		{
			tik.EnableSystemContentAccess(system_accessible_content[i]);
		}

		tik.SetTitleVersion(RESOLVE_SOURCE(getTitleVersion).get());
		tik.SetAccessTitleId(RESOLVE_SOURCE(getAccessTitleId).get());
		tik.SetAccessTitleIdMask(RESOLVE_SOURCE(getAccessTitleIdMask).get());
		tik.SetLicenseType(RESOLVE_SOURCE(getLicenseType).get());
		tik.SetEShopAccountId(RESOLVE_SOURCE(getEShopAccountId).get());
		tik.SetAudit(RESOLVE_SOURCE(getAudit).get());
		
		// limits
		const std::vector<UserSettings::sESLimit>& limits = RESOLVE_SOURCE(getLimits).get();
		for (size_t i = 0; limits.size(); i++)
		{
			tik.AddLimit(limits[i].key, limits[i].value);
		}

		// accessible content
		const std::vector<u16>& accessible_content = RESOLVE_SOURCE(getAccessibleContentList).get();
		for (size_t i = 0; i < accessible_content.size(); i++)
		{
			tik.EnableContent(accessible_content[i]);
		}

		static const Crypto::sRsa2048Key es_tik_key =
		{
			{ 0xC0, 0x84, 0x4C, 0xEB, 0x7E, 0xB0, 0xCF, 0xF0, 0xAE, 0xB7, 0x77, 0x69, 0x85, 0x93, 0xE4, 0x99, 0x5A, 0x95, 0x4E, 0x58, 0x17, 0x38, 0xCE, 0xD6, 0x81, 0xB0, 0xBD, 0x77, 0x09, 0xE7, 0xF8, 0x9A, 0xDF, 0xAD, 0x05, 0x48, 0x83, 0xF6, 0xC3, 0xFD, 0xDF, 0x7B, 0x83, 0xE0, 0x0C, 0x26, 0x81, 0x54, 0x43, 0x29, 0xEA, 0x82, 0x6C, 0x89, 0xF0, 0xA6, 0x74, 0x42, 0x86, 0x4D, 0x32, 0x60, 0x32, 0x7D, 0xA7, 0x7A, 0x13, 0x40, 0x66, 0x59, 0xDA, 0x3E, 0x41, 0x6B, 0x27, 0x94, 0x03, 0x4F, 0xAA, 0x22, 0x9D, 0xD5, 0x54, 0x52, 0xDB, 0x27, 0x0A, 0x6A, 0xA2, 0x3D, 0x19, 0xB1, 0x66, 0x1B, 0x19, 0x7D, 0xAB, 0xC7, 0x0E, 0x88, 0x17, 0x91, 0xA1, 0x2A, 0xB4, 0x3C, 0x6C, 0xCB, 0xF5, 0xAA, 0x7C, 0x3A, 0xDD, 0x36, 0xFB, 0x35, 0x71, 0x7B, 0x20, 0x01, 0x59, 0x00, 0xD6, 0xF6, 0x90, 0x39, 0x35, 0x41, 0x31, 0xF8, 0xC1, 0xC0, 0x57, 0x3A, 0x35, 0x18, 0x58, 0x90, 0xB1, 0xAD, 0x9A, 0x0E, 0xEC, 0xE0, 0xF4, 0x7A, 0x7D, 0xA5, 0x27, 0x48, 0xC9, 0x72, 0xAB, 0x0D, 0x08, 0x7B, 0x62, 0x35, 0x40, 0x91, 0x14, 0x2B, 0xB1, 0x1D, 0x1A, 0xFA, 0xF9, 0xCD, 0x5C, 0x17, 0x13, 0x53, 0x52, 0x71, 0xCA, 0xE2, 0x2A, 0x78, 0xB1, 0x7F, 0x4A, 0xCD, 0x59, 0xD8, 0xBA, 0x1D, 0x7D, 0x70, 0x5F, 0x78, 0x1B, 0x9F, 0x9D, 0x37, 0x18, 0x8E, 0xD7, 0xCD, 0x0D, 0x49, 0x57, 0x74, 0x69, 0x88, 0x3A, 0x6B, 0x8E, 0x4E, 0x1B, 0x85, 0xDD, 0xBE, 0x39, 0x45, 0x05, 0x89, 0x56, 0x12, 0x97, 0x59, 0x9A, 0x09, 0xA4, 0xC8, 0x2D, 0x2F, 0xF5, 0xCF, 0xB4, 0x73, 0x70, 0xDB, 0x58, 0x1E, 0xB2, 0x4E, 0x77, 0x6F, 0xA4, 0x7E, 0x62, 0xDF, 0xB7, 0x05, 0xE8, 0x80, 0x42, 0x5C, 0xB8, 0x78, 0x87, 0x97, 0x7F, 0x66, 0x2C, 0x5F },
			{ 0x74, 0xCB, 0xCF, 0x1E, 0xD0, 0x2D, 0xD4, 0xF9, 0xE0, 0x05, 0xCE, 0x9C, 0x66, 0x3D, 0xE3, 0x62, 0x66, 0x62, 0x4E, 0xB5, 0x82, 0xE1, 0x24, 0x1B, 0x5F, 0x73, 0x2A, 0x7F, 0x1D, 0xB3, 0x6E, 0x50, 0x07, 0x83, 0xA0, 0xC0, 0xED, 0xCE, 0xB7, 0xF9, 0x3D, 0xAC, 0x61, 0xC5, 0x7B, 0x99, 0xA0, 0xBC, 0xCE, 0x42, 0x8F, 0xD3, 0xB0, 0xA5, 0xBF, 0x2A, 0x3D, 0x3E, 0x5E, 0xDC, 0x56, 0xC3, 0xA5, 0xDE, 0x35, 0xCD, 0x0A, 0x00, 0xF8, 0x17, 0x6B, 0x20, 0x79, 0xEF, 0xD8, 0x83, 0x23, 0xBF, 0x21, 0x28, 0xFF, 0x38, 0x7D, 0x80, 0x07, 0x15, 0x18, 0x6C, 0xB9, 0x20, 0xF8, 0x85, 0x77, 0xBC, 0xD9, 0x2A, 0x35, 0x1C, 0xFE, 0xE3, 0xF1, 0xE8, 0x98, 0x2E, 0xA0, 0x4A, 0x48, 0x77, 0x35, 0x03, 0xC9, 0x7A, 0xAC, 0xDA, 0xBE, 0x6D, 0x1D, 0xFB, 0xE4, 0xDE, 0xEC, 0x70, 0x65, 0xFA, 0x10, 0x65, 0xA4, 0xB8, 0x6A, 0xDF, 0x32, 0x6B, 0x8E, 0x28, 0x79, 0x25, 0x87, 0x72, 0xC0, 0x7C, 0x5B, 0x81, 0xBC, 0x81, 0x92, 0x44, 0x7D, 0xEA, 0x61, 0xBD, 0x3C, 0x48, 0xF3, 0x0E, 0x18, 0xDC, 0x8D, 0x89, 0xA0, 0x34, 0xC3, 0xAE, 0x9C, 0x57, 0x72, 0xA6, 0xD7, 0x7C, 0x79, 0xF7, 0xE9, 0x14, 0x6E, 0x15, 0xAC, 0x01, 0xFA, 0xFF, 0xC8, 0xA2, 0x2A, 0x3A, 0xAB, 0x24, 0x3C, 0x7E, 0x2E, 0xC5, 0xDA, 0x83, 0xD5, 0x9D, 0x24, 0x10, 0x83, 0x7A, 0xF4, 0xBB, 0xA3, 0x6F, 0x88, 0xCE, 0xEC, 0x24, 0x1B, 0xF4, 0x36, 0x2E, 0x96, 0xC9, 0x6D, 0x19, 0x02, 0xFE, 0xAA, 0x21, 0x3E, 0x95, 0xA7, 0xFE, 0x83, 0xC8, 0x99, 0x7F, 0xD1, 0xCB, 0x7C, 0x1F, 0x91, 0x30, 0xDB, 0xA4, 0xD3, 0xDD, 0xDA, 0x9B, 0x12, 0x4E, 0x24, 0xD1, 0xA5, 0x6F, 0x15, 0xFC, 0x2C, 0x72, 0x98, 0x2C, 0x89, 0xC5, 0x7D, 0x89, 0xDE, 0x2B, 0x4E, 0x01 }
		};

		cfg.setSigningKey(es_tik_key);

		/* Serialise/Sign */
		switch (cfg.getSignType().get())
		{
		case (UserSettings::SIGN_RSA_2048):
			tik.SerialiseTicket(cfg.getSigningKeyRsa2048().get(), (ESTicket::ESTicketFormatVersion)RESOLVE_SOURCE(getFormatVersion).get());
			break;
		case (UserSettings::SIGN_RSA_4096):
			tik.SerialiseTicket(cfg.getSigningKeyRsa4096().get(), (ESTicket::ESTicketFormatVersion)RESOLVE_SOURCE(getFormatVersion).get());
			break;
		default:
			throw ProjectSnakeException("ES-TOOL", "Unsupported signature type");
		}

		// TODO: move this to a "FileIO::WriteFile()" in ESCertChain
		std::ofstream tikfile(cfg.getOutFilePath(), std::ios::binary);
		tikfile.write((const char*)tik.GetSerialisedData(), tik.GetSerialisedDataSize());
		tikfile.close();

#undef RESOLVE_SOURCE
	}
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
				// TODO: move this to a "operator=()" in ESCertChain
				certs.DeserialiseCertChain(cdn_raw.GetCerts().GetSerialisedData(), cdn_raw.GetCerts().GetSerialisedDataSize());
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
			DisplayEsFields::DisplayTmdFields(tmd, sign_state, cfg.doShowSignatures());

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
				throw ProjectSnakeException("ES-TOOL", "Unknown file type");
		}
	}
	catch (const ProjectSnakeException& e) {
		std::cout << "[" << e.module() << " ERROR] " << e.what() << std::endl;
		return 1;
	}
	return 0;
}