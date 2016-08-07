#pragma once
#include "types.h"

#include <string>
#include <vector>

#include "ByteBuffer.h"
#include "crypto.h"

#include "cia_header.h"
#include "es_cert.h"
#include "es_ticket.h"
#include "es_tmd.h"

class CiaBuilder
{
public:
	CiaBuilder();
	~CiaBuilder();

	int CreateCia();
	int WriteToFile(const std::string& path);
	int WriteToBuffer(ByteBuffer& out);

	int SetCaCert(const u8* cert);
	int SetTicketSigner(const Crypto::sRsa2048Key& rsa_key, const u8* cert);
	int SetTmdSigner(const Crypto::sRsa2048Key& rsa_key, const u8* cert);
	int AddContent(u32 id, u16 index, u16 flags, const u8* data, u64 size);

	int SetTitleKey(const u8* key);
	int SetCommonKey(const u8* key, u8 index);
	
	int SetTitleId(u64 title_id);
	int SetTicketId(u64 ticket_id);
	int SetCxiSaveDataSize(u32 size);
	//int SetSrlData(u8 flag, u32 public_save_data_size, u32 private_save_data_size);
	int SetVersion(u8 major, u8 minor, u8 build);
	int SetVersion(u16 version);
	
	
private:
	static const int kIoBufferLen = 0x100000;

	struct EsSigner {
		EsCert cert;
		Crypto::sRsa2048Key rsa_key;
	};

	struct ContentInfo {
		const u8* data;
		u32 id;
		u16 index;
		u16 flag;
		u64 size;
		u8 hash[Crypto::kSha256HashLen];
	};

	std::vector<u16> content_index_;
	std::vector<ContentInfo> content_;

	EsCert ca_cert_;
	EsSigner tik_sign_;
	EsSigner tmd_sign_;
	CiaHeader header_;
	ByteBuffer certs_;
	EsTicket tik_;
	EsTmd tmd_;
	ByteBuffer cxi_meta_;

	u64 total_content_size_;

	u64 ticket_id_;
	u64 title_id_;
	u16 title_version_;
	u32 save_data_size_;

	u8 titlekey_[Crypto::kAes128KeySize];
	u8 content_iv_[Crypto::kAesBlockSize];

	u8 commonkey_index_;
	u8 commonkey_[Crypto::kAes128KeySize];

	u8 io_buffer[kIoBufferLen];

	int MakeCertificateChain();
	int MakeTicket();
	int MakeTmd();
	int MakeHeader();

	void WriteContentBlockToFile(const u8* data, size_t size, bool encrypted, FILE* fp);
};