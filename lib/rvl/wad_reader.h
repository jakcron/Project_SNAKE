#pragma once
#include "types.h"
#include "crypto.h"


#include "wad_header.h"
#include "es_cert_chain.h"
#include "es_ticket.h"
#include "es_tmd.h"

class WadReader
{
public:
	struct sContentInfo
	{
		const u8* data;
		u32 id;
		u16 index;
		u16 flags;
		size_t size;
		u8 hash[Crypto::kSha256HashLen];
		bool is_tik_enabled;
	};

	WadReader();
	~WadReader();

	void ImportWad(const u8* wad_data);

	// common interaction
	u64 GetTitleId() const;
	u16 GetTitleVersion() const;
	u8 GetCommonKeyIndex() const;
	void SetCommonKey(const u8 common_key[Crypto::kAes128KeySize]);
	void SetTitleKey(const u8 title_key[Crypto::kAes128KeySize]);
	
	// section access for further processing
	const EsCertChain& GetCertificateChain() const;
	const EsTicket& GetTicket() const;
	const EsTmd& GetTmd() const;
	//const u8* GetFooter() const;
	//u32 GetFooterSize() const;

	// Access content
	const std::vector<sContentInfo>& GetContentList() const;
	void DecryptContentToBuffer(const sContentInfo& content, ByteBuffer& out);
	bool VerifyContent(const sContentInfo& content); // if the content is encrypted, it will be duplicated in memory, decrypted then verified 

													 // section validation
	bool ValidateCertificates(const Crypto::sRsa4096Key& root_key) const; // verifies all certificates, using the root key to check certificates signed by "Root"
	bool ValidateCertificatesExceptCa() const; // same as above, except certifcates with "Root" as parent aren't checked
	bool ValidateTicket() const; // verifies the ticket with the corresponding cert in the cert chain
	bool ValidateTmd() const; // verifies the tmd with the corresponding cert in the cert chain
private:
	const std::string kModuleName = "WAD_READER";

	WadHeader header_;
	EsCertChain certs_;
	EsTicket tik_;
	EsTmd tmd_;
	std::vector<sContentInfo> content_list_;
	ByteBuffer footer_;

	u8 title_key_[Crypto::kAes128KeySize];
};

