#pragma once
#include <string>
#include <vector>
#include <fnd/types.h>
#include <fnd/ByteBuffer.h>
#include <crypto/crypto.h>
#include <ctr/cia_header.h>
#include <ctr/cia_footer.h>
#include <es/es_cert_chain.h>
#include <es/es_ticket.h>
#include <es/es_tmd.h>
#include <es/es_content.h>

class CiaBuilder
{
public:
	CiaBuilder();
	~CiaBuilder();

	void CreateCia();
	void WriteToFile(const std::string& path);
	void WriteToBuffer(ByteBuffer& out);

	void SetCaCert(const u8* cert);
	void SetTicketSigner(const Crypto::sRsa2048Key& rsa_key, const u8* cert);
	void SetTmdSigner(const Crypto::sRsa2048Key& rsa_key, const u8* cert);
	void AddContent(u32 id, u16 index, u16 flags, const u8* data, u64 size);

	void SetTitleKey(const u8* key);
	void SetCommonKey(const u8* key, u8 index);
	
	void SetTitleId(u64 title_id);
	void SetTicketId(u64 ticket_id);
	void SetCxiSaveDataSize(u32 size);
	//void SetSrlData(u8 flag, u32 public_save_data_size, u32 private_save_data_size);
	void SetDemoLaunchLimit(u32 launch_num);
	void SetVersion(u8 major, u8 minor, u8 build);
	void SetVersion(u16 version);

	void SetFooter(const std::vector<u64>& dependency_list, u64 firmware_title_id, const u8* icon_data, size_t icon_size);
	
	
private:
	const std::string kModuleName = "CIA_BUILDER";

	static const int kIoBufferLen = 0x100000;

	struct ESSigner {
		ESCert cert;
		Crypto::sRsa2048Key rsa_key;
	};

	std::vector<ESContent> content_;

	ESCert ca_cert_;
	ESSigner tik_sign_;
	ESSigner tmd_sign_;
	CiaHeader header_;
	ESCertChain certs_;
	ESTicket tik_;
	ESTmd tmd_;
	CiaFooter footer_;

	u64 total_content_size_;

	u64 ticket_id_;
	u64 title_id_;
	u16 title_version_;
	u32 save_data_size_;

	u32 launch_num_;

	u8 titlekey_[Crypto::kAes128KeySize];
	u8 content_iv_[Crypto::kAesBlockSize];

	u8 commonkey_index_;
	u8 commonkey_[Crypto::kAes128KeySize];

	u8 io_buffer[kIoBufferLen];

	void MakeCertificateChain();
	void MakeTicket();
	void MakeTmd();
	void MakeHeader();

	void WriteContentBlockToFile(const u8* data, size_t size, bool encrypted, FILE* fp);
};