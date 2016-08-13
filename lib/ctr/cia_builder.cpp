#include "cia_builder.h"
#include "es_version.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

int CiaBuilder::MakeCertificateChain()
{
	certs_.alloc(ca_cert_.data_size() + tik_sign_.cert.data_size() + tmd_sign_.cert.data_size());
	memcpy(certs_.data() + 0, ca_cert_.data_blob(), ca_cert_.data_size());
	memcpy(certs_.data() + ca_cert_.data_size(), tik_sign_.cert.data_blob(), tik_sign_.cert.data_size());
	memcpy(certs_.data() + ca_cert_.data_size() + tik_sign_.cert.data_size(), tmd_sign_.cert.data_blob(), tmd_sign_.cert.data_size());

	return 0;
}

int CiaBuilder::MakeTicket()
{
	
	tik_.SetTicketId(ticket_id_);
	tik_.SetTitleVersion(title_version_);
	tik_.SetTitleId(title_id_);
	tik_.SetContentMask(content_index_);
	tik_.SetLicenseType(EsTicket::ES_LICENSE_PERMANENT);
	tik_.SetTitleKey(titlekey_, commonkey_, commonkey_index_);
	return tik_.CreateTicket(tik_sign_.cert.chlid_issuer(), tik_sign_.rsa_key.modulus, tik_sign_.rsa_key.priv_exponent);
}

int CiaBuilder::MakeTmd()
{
	tmd_.SetTitleId(title_id_);
	tmd_.SetTitleVersion(title_version_);
	tmd_.SetCxiData(save_data_size_);
	tmd_.SetTitleType(EsTmd::ES_TITLE_TYPE_CTR);


	total_content_size_ = 0;
	for (size_t i = 0; i < content_.size(); i++) {
		total_content_size_ += content_[i].size;
		tmd_.AddContent(content_[i].id, content_[i].index, content_[i].flag, content_[i].size, content_[i].hash);
	}

	return tmd_.CreateTitleMetadata(tmd_sign_.cert.chlid_issuer(), tmd_sign_.rsa_key.modulus, tmd_sign_.rsa_key.priv_exponent);
}

int CiaBuilder::MakeHeader()
{	
	header_.SetCertificateSize(certs_.size());
	header_.SetTicketSize(tik_.data_size());
	header_.SetTmdSize(tmd_.data_size());
	header_.SetMetaSize(cxi_meta_.size());
	header_.SetContentSize(total_content_size_);
	header_.SetContentMask(content_index_);
	return header_.CreateCiaHeader();
}

void CiaBuilder::WriteContentBlockToFile(const u8* data, size_t size, bool encrypted, FILE * fp)
{
	if (size > kIoBufferLen) return;

	if (encrypted) {
		Crypto::AesCbcEncrypt(data, size, titlekey_, content_iv_, io_buffer);
		fwrite(io_buffer, size, 1, fp);
	}
	else {
		fwrite(data, size, 1, fp);
	}

}


CiaBuilder::CiaBuilder()
{
}

CiaBuilder::~CiaBuilder()
{
}

int CiaBuilder::CreateCia()
{
	safe_call(MakeCertificateChain());
	safe_call(MakeTicket());
	safe_call(MakeTmd());
	safe_call(MakeHeader());

	return 0;
}

int CiaBuilder::WriteToFile(const std::string & path)
{
	FILE* fp;

	fp = fopen(path.c_str(), "wb");

	u8 padding[0x400] = { 0 };

	// header
	fwrite(header_.data_blob(), header_.data_size(), 1, fp);
	fwrite(padding, header_.certificate_offset() - header_.data_size(), 1, fp);

	// certificates
	fwrite(certs_.data_const(), certs_.size(), 1, fp);
	fwrite(padding, header_.ticket_offset() - (header_.certificate_offset() + header_.certificate_size()), 1, fp);

	// ticket
	fwrite(tik_.data_blob(), tik_.data_size(), 1, fp);
	fwrite(padding, header_.title_metadata_offset() - (header_.ticket_offset() + header_.ticket_size()), 1, fp);

	// tmd
	fwrite(tmd_.data_blob(), tmd_.data_size(), 1, fp);
	fwrite(padding, header_.content_offset() - (header_.title_metadata_offset() + header_.title_metadata_size()), 1, fp);

	// content
	for (size_t i = 0; i < content_.size(); i++) {
		if (content_[i].flag & EsTmd::ES_CONTENT_TYPE_ENCRYPTED) {
			EsCrypto::SetupContentAesIv(content_[i].index, content_iv_);
		}

		// write blocks
		for (size_t j = 0; j < (content_[i].size / kIoBufferLen); j++) {
			WriteContentBlockToFile(content_[i].data + (kIoBufferLen * j), kIoBufferLen, content_[i].flag & EsTmd::ES_CONTENT_TYPE_ENCRYPTED, fp);
		}

		// write final unaligned block
		if (content_[i].size % kIoBufferLen) {
			WriteContentBlockToFile(content_[i].data + ((content_[i].size / kIoBufferLen) * kIoBufferLen), content_[i].size % kIoBufferLen, content_[i].flag & EsTmd::ES_CONTENT_TYPE_ENCRYPTED, fp);
		}
	}

	// meta
	if (header_.cxi_metadata_size() > 0) {
		fwrite(padding, header_.cxi_metadata_offset() - (header_.content_offset() + header_.content_size()), 1, fp);
		fwrite(cxi_meta_.data_const(), cxi_meta_.size(), 1, fp);
	}

	return 0;
}

int CiaBuilder::WriteToBuffer(ByteBuffer& out)
{
	// allocate projected CIA size
	safe_call(out.alloc(header_.cia_size()));

	// copy data to buffer
	memcpy(out.data() + 0x0, header_.data_blob(), header_.data_size());
	memcpy(out.data() + header_.certificate_offset(), certs_.data_const(), certs_.size());
	memcpy(out.data() + header_.ticket_offset(), tik_.data_blob(), tik_.data_size());
	memcpy(out.data() + header_.title_metadata_offset(), tmd_.data_blob(), tmd_.data_size());
	memcpy(out.data() + header_.cxi_metadata_offset(), cxi_meta_.data_const(), cxi_meta_.size());

	u64 pos = header_.content_offset();
	for (size_t i = 0; i < content_.size(); i++) {
		if (content_[i].flag & EsTmd::ES_CONTENT_TYPE_ENCRYPTED) {
			EsCrypto::SetupContentAesIv(content_[i].index, content_iv_);
			Crypto::AesCbcEncrypt(content_[i].data, content_[i].size, titlekey_, content_iv_, out.data() + pos);
		}
		else {
			memcpy(out.data() + pos, content_[i].data, content_[i].size);
		}


		pos += content_[i].size;
	}

	return 0;
}


int CiaBuilder::SetCaCert(const u8 * cert)
{
	return ca_cert_.ImportCert(cert);
}

int CiaBuilder::SetTicketSigner(const Crypto::sRsa2048Key & rsa_key, const u8 * cert)
{
	tik_sign_.cert.ImportCert(cert);
	memcpy(tik_sign_.rsa_key.modulus, rsa_key.modulus, Crypto::kRsa2048Size);
	memcpy(tik_sign_.rsa_key.priv_exponent, rsa_key.priv_exponent, Crypto::kRsa2048Size);
	return 0;
}

int CiaBuilder::SetTmdSigner(const Crypto::sRsa2048Key & rsa_key, const u8 * cert)
{
	tmd_sign_.cert.ImportCert(cert);
	memcpy(tmd_sign_.rsa_key.modulus, rsa_key.modulus, Crypto::kRsa2048Size);
	memcpy(tmd_sign_.rsa_key.priv_exponent, rsa_key.priv_exponent, Crypto::kRsa2048Size);
	return 0;
}

int CiaBuilder::AddContent(u32 id, u16 index, u16 flags, const u8* data, u64 size)
{
	ContentInfo info;
	info.id = id;
	info.index = index;
	info.flag = flags;
	info.data = data;
	info.size = size;
	Crypto::Sha256(info.data, info.size, info.hash);

	content_index_.push_back(info.index);
	content_.push_back(info);

	return 0;
}

int CiaBuilder::SetTitleKey(const u8 * key)
{
	memcpy(titlekey_, key, Crypto::kAes128KeySize);
	return 0;
}

int CiaBuilder::SetCommonKey(const u8 * key, u8 index)
{
	commonkey_index_ = index;
	memcpy(commonkey_, key, Crypto::kAes128KeySize);
	return 0;
}

int CiaBuilder::SetTitleId(u64 title_id)
{
	title_id_ = title_id;
	return 0;
}

int CiaBuilder::SetTicketId(u64 ticket_id)
{
	ticket_id_ = ticket_id;
	return 0;
}

int CiaBuilder::SetCxiSaveDataSize(u32 size)
{
	save_data_size_ = size;
	return 0;
}

int CiaBuilder::SetVersion(u8 major, u8 minor, u8 build)
{
	title_version_ = EsVersion::make_version(major, minor, build);
	return 0;
}

int CiaBuilder::SetVersion(u16 version)
{
	title_version_ = version;
	return 0;
}