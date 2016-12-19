#pragma once
#include <fnd/types.h>
#include <fnd/ByteBuffer.h>
#include <crypto/crypto.h>
#include <ctr/cia_header.h>
#include <ctr/cia_footer.h>
#include <es/es_crypto.h>
#include <es/es_content.h>
#include <es/es_cert_chain.h>
#include <es/es_ticket.h>
#include <es/es_tmd.h>


class CiaReader
{
public:
	CiaReader();
	~CiaReader();

	void ImportCia(const u8* cia_data);
	
	// common interaction
	u64 GetTitleId() const;
	u16 GetTitleVersion() const;
	u8 GetCommonKeyIndex() const;
	u32 GetCtrSaveSize() const;
	u32 GetTwlPublicSaveSize() const;
	u32 GetTwlPrivateSaveSize() const;
	u8 GetSrlFlag() const;
	const u8* GetTitleKey(const u8* common_key);

	// section access for further processing
	const ESCertChain& GetCertificateChain() const;
	const ESTicket& GetTicket() const;
	const ESTmd& GetTmd() const;
	const CiaFooter& GetFooter() const;

	// Access content
	std::vector<ESContent>& GetContentList();

	// section validation
	bool ValidateCertificates(const Crypto::sRsa4096Key& root_key) const; // verifies all certificates, using the root key to check certificates signed by "Root"
	bool ValidateCertificatesExceptCa() const; // same as above, except certifcates with "Root" as parent aren't checked
	bool ValidateTicket() const; // verifies the ticket with the corresponding cert in the cert chain
	bool ValidateTmd() const; // verifies the tmd with the corresponding cert in the cert chain

private:
	const std::string kModuleName = "CIA_READER";

	CiaHeader header_;
	ESCertChain certs_;
	ESTicket tik_;
	ESTmd tmd_;
	std::vector<ESContent> content_list_;
	CiaFooter footer_;

	// tmd platform reserved data
	u32 ctr_save_size_;
	u32 twl_public_save_size_;
	u32 twl_private_save_size_;
	u8 srl_flag_;

	void DeserialiseTmdPlatformReservedData();
};

