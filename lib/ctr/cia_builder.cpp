#include "cia_builder.h"
#include "es_version.h"

#include "program_id.h"

void CiaBuilder::MakeCertificateChain()
{
	certs_.AddCertificate(ca_cert_);
	certs_.AddCertificate(tik_sign_.cert);
	certs_.AddCertificate(tmd_sign_.cert);
	certs_.SerialiseCertChain();
}

void CiaBuilder::MakeTicket()
{
	tik_.SetTicketId(ticket_id_);
	tik_.SetTitleVersion(title_version_);
	tik_.SetTitleId(title_id_);
	tik_.SetLicenseType(EsTicket::ES_LICENSE_PERMANENT);
	
	// enable all contents' indexes
	for (auto& content : content_)
	{
		tik_.EnableContent(content.index);
	}

	// enable demo launch restriction
	if (launch_num_ > 0 && ProgramId::get_category(title_id_) == ProgramId::CATEGORY_DEMO)
	{
		tik_.AddLimit(tik_.ES_LC_NUM_LAUNCH, launch_num_);
	}

	// set title key data
	tik_.SetTitleKey(titlekey_, commonkey_);
	tik_.SetCommonKeyIndex(commonkey_index_);
	
	// set signature/format data + serialise
	tik_.SetIssuer(tik_sign_.cert.GetChildIssuer());
	tik_.SetFormatVersion(1);
	tik_.SetCaCrlVersion(0);
	tik_.SetSignerCrlVersion(0);
	tik_.SerialiseTicket(tik_sign_.rsa_key);
}

void CiaBuilder::MakeTmd()
{
	tmd_.SetTitleId(title_id_);
	tmd_.SetTitleVersion(title_version_);
	tmd_.SetCtrSaveSize(save_data_size_);
	tmd_.SetTitleType(EsTmd::ES_TITLE_TYPE_CTR);


	total_content_size_ = 0;
	for (size_t i = 0; i < content_.size(); i++) {
		total_content_size_ += content_[i].size;
		tmd_.AddContent(content_[i].id, content_[i].index, content_[i].flag, content_[i].size, content_[i].hash);
	}

	tmd_.SetIssuer(tmd_sign_.cert.GetChildIssuer());
	tmd_.SetFormatVersion(1);
	tmd_.SetCaCrlVersion(0);
	tmd_.SetSignerCrlVersion(0);
	tmd_.SerialiseTmd(tmd_sign_.rsa_key);
}

void CiaBuilder::MakeHeader()
{	
	header_.SetCertificateChainSize(certs_.GetSerialisedDataSize());
	header_.SetTicketSize(tik_.GetSerialisedDataSize());
	header_.SetTmdSize(tmd_.GetSerialisedDataSize());
	header_.SetCxiMetaDataSize(cxi_meta_.GetSerialisedDataSize());
	header_.SetContentSize(total_content_size_);
	// enable all contents' indexes
	for (auto& content : content_)
	{
		header_.EnableContent(content.index);
	}
	header_.SerialiseHeader();
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

void CiaBuilder::CreateCia()
{
	MakeCertificateChain();
	MakeTicket();
	MakeTmd();
	MakeHeader();
}

void CiaBuilder::WriteToFile(const std::string & path)
{
	FILE* fp;

	fp = fopen(path.c_str(), "wb");
	if (fp == NULL)
	{
		throw ProjectSnakeException(kModuleName, "Failed to open " + path + " for writing");
	}

	u8 padding[0x400] = { 0 };

	// header
	fwrite(header_.GetSerialisedData(), header_.GetSerialisedDataSize(), 1, fp);
	fwrite(padding, header_.GetCertificateChainOffset() - header_.GetSerialisedDataSize(), 1, fp);

	// certificates
	fwrite(certs_.GetSerialisedData(), certs_.GetSerialisedDataSize(), 1, fp);
	fwrite(padding, header_.GetTicketOffset() - (header_.GetCertificateChainOffset() + header_.GetCertificateChainSize()), 1, fp);

	// ticket
	fwrite(tik_.GetSerialisedData(), tik_.GetSerialisedDataSize(), 1, fp);
	fwrite(padding, header_.GetTmdOffset() - (header_.GetTicketOffset() + header_.GetTicketSize()), 1, fp);

	// tmd
	fwrite(tmd_.GetSerialisedData(), tmd_.GetSerialisedDataSize(), 1, fp);
	fwrite(padding, header_.GetContentOffset() - (header_.GetTmdOffset() + header_.GetTmdSize()), 1, fp);

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
	if (header_.GetCxiMetaDataSize() > 0) {
		fwrite(padding, header_.GetCxiMetaDataOffset() - (header_.GetContentOffset() + header_.GetContentSize()), 1, fp);
		fwrite(cxi_meta_.GetSerialisedData(), cxi_meta_.GetSerialisedDataSize(), 1, fp);
	}
}

void CiaBuilder::WriteToBuffer(ByteBuffer& out)
{
	// allocate projected CIA size
	if (out.alloc(header_.GetPredictedCiaSize()) != out.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for CIA");
	}

	// copy data to buffer
	memcpy(out.data() + 0x0, header_.GetSerialisedData(), header_.GetSerialisedDataSize());
	memcpy(out.data() + header_.GetCertificateChainOffset(), certs_.GetSerialisedData(), certs_.GetSerialisedDataSize());
	memcpy(out.data() + header_.GetTicketOffset(), tik_.GetSerialisedData(), tik_.GetSerialisedDataSize());
	memcpy(out.data() + header_.GetTmdOffset(), tmd_.GetSerialisedData(), tmd_.GetSerialisedDataSize());
	memcpy(out.data() + header_.GetCxiMetaDataOffset(), cxi_meta_.GetSerialisedData(), cxi_meta_.GetSerialisedDataSize());

	u64 pos = header_.GetContentOffset();
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
}


void CiaBuilder::SetCaCert(const u8 * cert)
{
	ca_cert_.DeserialiseCert(cert);
}

void CiaBuilder::SetTicketSigner(const Crypto::sRsa2048Key & rsa_key, const u8 * cert)
{
	tik_sign_.cert.DeserialiseCert(cert);
	memcpy(tik_sign_.rsa_key.modulus, rsa_key.modulus, Crypto::kRsa2048Size);
	memcpy(tik_sign_.rsa_key.priv_exponent, rsa_key.priv_exponent, Crypto::kRsa2048Size);
}

void CiaBuilder::SetTmdSigner(const Crypto::sRsa2048Key & rsa_key, const u8 * cert)
{
	tmd_sign_.cert.DeserialiseCert(cert);
	memcpy(tmd_sign_.rsa_key.modulus, rsa_key.modulus, Crypto::kRsa2048Size);
	memcpy(tmd_sign_.rsa_key.priv_exponent, rsa_key.priv_exponent, Crypto::kRsa2048Size);
}

void CiaBuilder::AddContent(u32 id, u16 index, u16 flags, const u8* data, u64 size)
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
}

void CiaBuilder::SetTitleKey(const u8 * key)
{
	memcpy(titlekey_, key, Crypto::kAes128KeySize);
}

void CiaBuilder::SetCommonKey(const u8 * key, u8 index)
{
	commonkey_index_ = index;
	memcpy(commonkey_, key, Crypto::kAes128KeySize);
}

void CiaBuilder::SetTitleId(u64 title_id)
{
	title_id_ = title_id;
}

void CiaBuilder::SetTicketId(u64 ticket_id)
{
	ticket_id_ = ticket_id;
}

void CiaBuilder::SetCxiSaveDataSize(u32 size)
{
	save_data_size_ = size;
}

void CiaBuilder::SetDemoLaunchLimit(u32 launch_num)
{
	launch_num_ = launch_num;
}

void CiaBuilder::SetVersion(u8 major, u8 minor, u8 build)
{
	SetVersion(EsVersion::make_version(major, minor, build));
}

void CiaBuilder::SetVersion(u16 version)
{
	title_version_ = version;
}

void CiaBuilder::SetCxiMetaData(const std::vector<u64>& dependency_list, u64 firmware_title_id, const u8* icon_data, size_t icon_size)
{
	cxi_meta_.SetDependencyList(dependency_list);
	cxi_meta_.SetFirmwareTitleId(firmware_title_id);
	if (icon_size > 0 && icon_data != NULL)
	{
		cxi_meta_.SetIcon(icon_data, icon_size);
	}
	cxi_meta_.SerialiseMetaData();
}
