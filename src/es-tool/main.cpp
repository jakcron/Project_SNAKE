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
		if (set.GetFileType() == set.FILE_CERTS)
		{
			ESCertChain certs;

			// read data
			if (set.GetInFilePath().empty() != false)
			{
				FileIO::ReadFile(set.GetInFilePath(), blob);

				// deserialise certificate
				certs.DeserialiseCertChain(blob.data(), blob.size());

				// print data
				if (set.DoPrintData())
				{
					// if certificates were appended, validate ticket
					DisplayEsFields::SigState signValid;
					if (certs.GetCertificateNum() > 0 && set.DoUseCdnCertToVerify())
					{
						try {
							signValid = certs[0].ValidateSignature(certs[certs[0].GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
						}
						catch (const ProjectSnakeException& e) {
							signValid = DisplayEsFields::SIG_INVALID;
						}
					}
					// if requested use externel certificates
					else if (set.DoUseExternalCertToVerify())
					{
						MemoryBlob certs_data;
						FileIO::ReadFile(set.GetExternalCertPath(), certs_data);
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
					DisplayEsFields::DisplayCertFields(certs[0], signValid, set.DoShowSignatures(), set.DoShowFullPublicKeys());

					// show cdn certs
					if (set.DoShowCdnCerts())
					{
						for (size_t i = 1; i < certs.GetCertificates().size(); i++)
						{
							DisplayEsFields::DisplayCertFields(certs[i], DisplayEsFields::SIG_UNCHECKED, set.DoShowSignatures(), set.DoShowFullPublicKeys());
						}
					}
				}
			}

			
		}
		// else tik
		else if (set.GetFileType() == set.FILE_TIK)
		{
			ESCdnTicket tik;
			
			// read data
			if (set.GetInFilePath().empty() != false)
			{
				// open file
				FileIO::ReadFile(set.GetInFilePath(), blob);

				// deserialise ticket
				tik.DeserialiseTicket(blob.data(), blob.size());

				// print info
				if (set.DoPrintData())
				{
					// if certificates were appended, validate ticket
					DisplayEsFields::SigState signValid;
					if (tik.GetCerts().GetCertificateNum() > 0 && set.DoUseCdnCertToVerify())
					{
						try {
							signValid = tik.GetTicket().ValidateSignature(tik.GetCerts()[tik.GetTicket().GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
						}
						catch (const ProjectSnakeException& e) {
							signValid = DisplayEsFields::SIG_UNCHECKED;
						}
					}
					// if requested use externel certificates
					else if (set.DoUseExternalCertToVerify())
					{
						MemoryBlob certs_data;
						FileIO::ReadFile(set.GetExternalCertPath(), certs_data);
						ESCertChain certs;
						certs.DeserialiseCertChain(certs_data.data(), certs_data.size());

						try {
							signValid = tik.GetTicket().ValidateSignature(certs[tik.GetTicket().GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
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
					DisplayEsFields::DisplayTicketFields(tik.GetTicket(), signValid, nullptr, set.DoShowSignatures(), set.DoShowFullPublicKeys());

					// show cdn certs
					if (set.DoShowCdnCerts())
					{
						for (size_t i = 0; i < tik.GetCerts().GetCertificates().size(); i++)
						{
							DisplayEsFields::DisplayCertFields(tik.GetCerts().GetCertificates()[i], DisplayEsFields::SIG_UNCHECKED, set.DoShowSignatures(), set.DoShowFullPublicKeys());
						}
					}
				}
			}

			// create data
		}
		// else tmd
		else if (set.GetFileType() == set.FILE_TMD)
		{
			ESCdnTmd tmd;

			// read data
			if (set.GetInFilePath().empty() != false)
			{
				// open file
				FileIO::ReadFile(set.GetInFilePath(), blob);

				// deserialise tmd
				tmd.DeserialiseTmd(blob.data(), blob.size());

				// print data
				if (set.DoPrintData())
				{
					// if certificates were appended, validate tmd
					DisplayEsFields::SigState signValid;
					if (tmd.GetCerts().GetCertificateNum() > 0 && set.DoUseCdnCertToVerify())
					{
						try {
							signValid = tmd.GetTmd().ValidateSignature(tmd.GetCerts()[tmd.GetTmd().GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
						}
						catch (const ProjectSnakeException& e) {
							signValid = DisplayEsFields::SIG_UNCHECKED;
						}
					}
					// if requested use externel certificates
					else if (set.DoUseExternalCertToVerify())
					{
						MemoryBlob certs_data;
						FileIO::ReadFile(set.GetExternalCertPath(), certs_data);
						ESCertChain certs;
						certs.DeserialiseCertChain(certs_data.data(), certs_data.size());

						try {
							signValid = tmd.GetTmd().ValidateSignature(certs[tmd.GetTmd().GetIssuer()]) ? DisplayEsFields::SIG_VALID : DisplayEsFields::SIG_INVALID;
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
					DisplayEsFields::DisplayTmdFields(tmd.GetTmd(), signValid, set.DoShowSignatures());

					// show cdn certs
					if (set.DoShowCdnCerts())
					{
						for (size_t i = 0; i < tmd.GetCerts().GetCertificates().size(); i++)
						{
							DisplayEsFields::DisplayCertFields(tmd.GetCerts().GetCertificates()[i], DisplayEsFields::SIG_UNCHECKED, set.DoShowSignatures(), set.DoShowFullPublicKeys());
						}
					}
				}
			}
			
			// create data
			if (set.GetOutFilePath().empty() == false)
			{
				ESTmd new_tmd;
				//if ()
			}
			

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