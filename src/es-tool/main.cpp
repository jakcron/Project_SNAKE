#include "user_settings.h"
#include "display_es_fields.h"
#include <iostream>
#include <fnd/memory_blob.h>
#include <fnd/file_io.h>
#include <es/es_cert_chain.h>
#include <es/es_cdn_ticket.h>
#include <es/es_cdn_tmd.h>

int main(int argc, char** argv)
{
	try {
		MemoryBlob blob;
		UserSettings set(argc, argv);

		// if certs
		if (set.getFileType() == set.FILE_CERTS)
		{
			ESCertChain certs;

			// read data
			if (!set.getInFilePath().empty())
			{
				FileIO::ReadFile(set.getInFilePath(), blob);

				// deserialise certificate
				certs.DeserialiseCertChain(blob.data(), blob.size());

				// print data
				if (set.doPrintData())
				{
					// if certificates were appended, validate ticket
					DisplayEsFields::SigState signValid;
					if (certs.GetCertificateNum() > 0 && set.doUseCdnCertToVerify())
					{
						try {
							signValid = certs[0].ValidateSignature(certs[certs[0].GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
						}
						catch (const ProjectSnakeException& e) {
							signValid = DisplayEsFields::SIG_INVALID;
						}
					}
					// if requested use externel certificates
					else if (set.doUseExternalCertToVerify())
					{
						MemoryBlob certs_data;
						FileIO::ReadFile(set.getExternalCertPath(), certs_data);
						ESCertChain certs_other;
						certs_other.DeserialiseCertChain(certs_data.data(), certs_data.size());

						try {
							signValid = certs[0].ValidateSignature(certs_other[certs[0].GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
						}
						catch (const ProjectSnakeException& e) {
							signValid = DisplayEsFields::SIG_INVALID;
						}
					}
					else
					{
						signValid = DisplayEsFields::SIG_UNCHECKED;
					}

					// show ticket fields
					DisplayEsFields::DisplayCertFields(certs[0], signValid, set.doShowSignatures(), set.doShowFullPublicKeys());

					// show cdn certs
					if (set.doShowCdnCerts())
					{
						for (size_t i = 1; i < certs.GetCertificates().size(); i++)
						{
							DisplayEsFields::DisplayCertFields(certs[i], DisplayEsFields::SIG_UNCHECKED, set.doShowSignatures(), set.doShowFullPublicKeys());
						}
					}
				}
			}

			
		}
		// else tik
		else if (set.getFileType() == set.FILE_TIK)
		{
			ESCdnTicket cdn_raw;
			
			// read data
			if (!set.getInFilePath().empty())
			{
				// open file
				FileIO::ReadFile(set.getInFilePath(), blob);

				// deserialise ticket
				cdn_raw.DeserialiseTicket(blob.data(), blob.size());
				ESTicket etik = cdn_raw.GetTicket();

				// set ticket user data
				set.setFormatVersion(etik.GetFormatVersion());
				set.setTitleId(etik.GetTitleId());
				set.setVersion(etik.GetTitleVersion());
				set.setCaCrlVersion(etik.GetCaCrlVersion());
				set.setSignerCrlVersion(etik.GetSignerCrlVersion());
				set.setTicketId(etik.GetTicketId());
				set.setEscrowKeyId(etik.GetCommonKeyIndex());
				// TODO title key vs escrowed title key logic
				// pull out decrypted title key? and reencrypted? use cases?
				set.setEscrowedTitleKey(etik.GetEncryptedTitleKey());
				set.setDeviceId(etik.GetDeviceId());
				set.setSystemAccessibleContent(etik.GetSystemAccessibleContentList());
				set.setAccessTitleId(etik.GetAccessTitleId());
				set.setAccessTitleIdMask(etik.GetAccessTitleIdMask());
				set.setLicenseType(etik.GetLicenseType());
				for (size_t i = 0; i < ESTicket::ES_MAX_LIMIT_TYPE; i++)
				{

				}

				// print info
				if (set.doPrintData())
				{
					// if certificates were appended, validate ticket
					DisplayEsFields::SigState signValid;
					if (cdn_raw.GetCerts().GetCertificateNum() > 0 && set.doUseCdnCertToVerify())
					{
						try {
							signValid = cdn_raw.GetTicket().ValidateSignature(cdn_raw.GetCerts()[cdn_raw.GetTicket().GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
						}
						catch (const ProjectSnakeException& e) {
							signValid = DisplayEsFields::SIG_UNCHECKED;
						}
					}
					// if requested use externel certificates
					else if (set.doUseExternalCertToVerify())
					{
						MemoryBlob certs_data;
						FileIO::ReadFile(set.getExternalCertPath(), certs_data);
						ESCertChain certs;
						certs.DeserialiseCertChain(certs_data.data(), certs_data.size());

						try {
							signValid = cdn_raw.GetTicket().ValidateSignature(certs[cdn_raw.GetTicket().GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
						}
						catch (const ProjectSnakeException& e) {
							signValid = DisplayEsFields::SIG_INVALID;
						}
					}
					else
					{
						signValid = DisplayEsFields::SIG_UNCHECKED;
					}

					// show ticket fields
					DisplayEsFields::DisplayTicketFields(cdn_raw.GetTicket(), signValid, nullptr, set.doShowSignatures(), set.doShowFullPublicKeys());

					// show cdn certs
					if (set.doShowCdnCerts())
					{
						for (size_t i = 0; i < cdn_raw.GetCerts().GetCertificates().size(); i++)
						{
							DisplayEsFields::DisplayCertFields(cdn_raw.GetCerts().GetCertificates()[i], DisplayEsFields::SIG_UNCHECKED, set.doShowSignatures(), set.doShowFullPublicKeys());
						}
					}
				}
			}

			// create data
		}
		// else tmd
		else if (set.getFileType() == set.FILE_TMD)
		{
			ESCdnTmd input_tmd;

			// read data
			if (!set.getInFilePath().empty())
			{
				// open file
				FileIO::ReadFile(set.getInFilePath(), blob);

				// deserialise tmd
				input_tmd.DeserialiseTmd(blob.data(), blob.size());

				// print data
				if (set.doPrintData())
				{
					// if certificates were appended, validate tmd
					DisplayEsFields::SigState signValid;
					if (input_tmd.GetCerts().GetCertificateNum() > 0 && set.doUseCdnCertToVerify())
					{
						try {
							signValid = input_tmd.GetTmd().ValidateSignature(input_tmd.GetCerts()[input_tmd.GetTmd().GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
						}
						catch (const ProjectSnakeException& e) {
							signValid = DisplayEsFields::SIG_UNCHECKED;
						}
					}
					// if requested use externel certificates
					else if (set.doUseExternalCertToVerify())
					{
						MemoryBlob certs_data;
						FileIO::ReadFile(set.getExternalCertPath(), certs_data);
						ESCertChain certs;
						certs.DeserialiseCertChain(certs_data.data(), certs_data.size());

						try {
							signValid = input_tmd.GetTmd().ValidateSignature(certs[input_tmd.GetTmd().GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
						}
						catch (const ProjectSnakeException& e) {
							signValid = DisplayEsFields::SIG_INVALID;
						}
					}
					else
					{
						signValid = DisplayEsFields::SIG_UNCHECKED;
					}

					// show tmd fields
					DisplayEsFields::DisplayTmdFields(input_tmd.GetTmd(), signValid, set.doShowSignatures());

					// show cdn certs
					if (set.doShowCdnCerts())
					{
						for (size_t i = 0; i < input_tmd.GetCerts().GetCertificates().size(); i++)
						{
							DisplayEsFields::DisplayCertFields(input_tmd.GetCerts().GetCertificates()[i], DisplayEsFields::SIG_UNCHECKED, set.doShowSignatures(), set.doShowFullPublicKeys());
						}
					}
				}
			}
			
			// create data
			/*
			if (set.GetOutFilePath().empty() == false)
			{
				ESTmd new_tmd;
				if (set.GetInFilePath().empty() == false)
				{
					new_tmd = input_tmd.GetTmd();
				}
				else
				{
					if (set)
				}
			}
			*/

			/*
			algo:

			using existing file as base?
			-> edit data if set, reclaim format version too
			-> create new, prompting for input when not provided
			*/

			/*
			new_tmd = tmd.GetTmd();
			ESTmd::ESTmdFormatVersion formatVersion;
			
			// determine format version
			if (set.IsFormatVersionSet())
			{
				formatVersion = (ESTmd::ESTmdFormatVersion)set.GetFormatVersion();
				switch (formatVersion)
				{
				case (ESTmd::ES_TMD_VER_0):
				case (ESTmd::ES_TMD_VER_1):
					break;
				default:
					throw ProjectSnakeException("ES-TOOL", "Invalid TMD format version: " + set.GetFormatVersion());
				}
			}
			else
			{
				formatVersion = ESTmd::ES_TMD_VER_1;
			}

			if (set.IsTitleIdSet())
			{
				new_tmd.SetTitleId(set.GetTitleId());
			}
			else if (new_tmd.GetTitleId() == 0)
			{
				throw ProjectSnakeException("ES-TOOL", "--titleid not set");
			}

			if (set.IsVersionSet())
			{
				new_tmd.SetTitleVersion(set.GetVersion());
			}

			Crypto::sRsa2048Key key;
			new_tmd.SerialiseTmd(key, formatVersion);
			*/
		}
	}
	catch (const ProjectSnakeException& e) {
		std::cout << "[" << e.module() << " ERROR] " << e.what() << std::endl;
		return 1;
	}
	return 0;
}