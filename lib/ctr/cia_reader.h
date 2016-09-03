#pragma once

#include "types.h"
#include "ByteBuffer.h"
#include "crypto.h"
#include "es_crypto.h"

#include "cia_header.h"
#include "es_cert_chain.h"
#include "es_ticket.h"
#include "es_tmd.h"
#include "cia_cxi_meta_data.h"

class CiaReader
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
		bool is_cia_enabled;
		bool is_tik_enabled;
	};

	CiaReader();
	~CiaReader();

	void ImportCia(const u8* cia_data);
	
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
	const CiaCxiMetaData& GetCxiMetaData() const;

	// Access content
	const std::vector<sContentInfo>& GetContentList() const;
	void DecryptContentToBuffer(const sContentInfo& content, ByteBuffer& out);
	bool VerifyContent(const sContentInfo& content); // if the content is encrypted, it will be duplicated in memory, decrypted then verified 

private:
	const std::string kModuleName = "CIA_READER";

	CiaHeader header_;
	EsCertChain certs_;
	EsTicket tik_;
	EsTmd tmd_;
	std::vector<sContentInfo> content_list_;
	CiaCxiMetaData meta_data_;

	u8 title_key_[Crypto::kAes128KeySize];
};

