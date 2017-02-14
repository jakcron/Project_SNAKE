#include <es/es_version.h>
#include "cia_builder.h"

#include "ctr_program_id.h"
#include "ctr_tmd_reserved_data.h"

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
	tik_.SetLicenseType(ESTicket::ES_LICENSE_PERMANENT);
	
	// enable all contents' indexes
	for (auto& content : content_)
	{
		tik_.EnableContent(content.GetContentIndex());
	}

	// enable demo launch restriction
	if (launch_num_ > 0 && CtrProgramId::get_category(title_id_) == CtrProgramId::CATEGORY_DEMO)
	{
		tik_.AddLimit(tik_.ES_LC_NUM_LAUNCH, launch_num_);
	}

	// set title key data
	tik_.SetTitleKey(titlekey_, commonkey_);
	tik_.SetCommonKeyIndex(commonkey_index_);
	
	// set signature/format data + serialise
	tik_.SetIssuer(tik_sign_.cert.GetChildIssuer());
	tik_.SetCaCrlVersion(0);
	tik_.SetSignerCrlVersion(0);
	tik_.SerialiseTicket(tik_sign_.rsa_key);
}

void CiaBuilder::MakeTmd()
{
	sCtrTmdPlatormReservedRegion ctr_region;
	ctr_region.clear();
	ctr_region.set_public_save_data_size(save_data_size_);

	tmd_.SetTitleId(title_id_);
	tmd_.SetTitleVersion(title_version_);
	tmd_.SetPlatformReservedData((const u8*)&ctr_region, sizeof(sCtrTmdPlatormReservedRegion));
	tmd_.SetTitleType(ESTmd::ES_TITLE_TYPE_CTR);


	total_content_size_ = 0;
	for (size_t i = 0; i < content_.size(); i++) {
		total_content_size_ += content_[i].GetSize();
		tmd_.AddContent(content_[i]);
	}

	tmd_.SetIssuer(tmd_sign_.cert.GetChildIssuer());
	tmd_.SetCaCrlVersion(0);
	tmd_.SetSignerCrlVersion(0);
	tmd_.SerialiseTmd(tmd_sign_.rsa_key);
}

void CiaBuilder::MakeHeader()
{	
	header_.SetCertificateChainSize(certs_.GetSerialisedDataSize());
	header_.SetTicketSize(tik_.GetSerialisedDataSize());
	header_.SetTmdSize(tmd_.GetSerialisedDataSize());
	header_.SetFooterSize(footer_.GetSerialisedDataSize());
	header_.SetContentSize(total_content_size_);
	// enable all contents' indexes
	for (auto& content : content_)
	{
		header_.EnableContent(content.GetContentIndex());
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
		bool is_content_encrypted = content_[i].IsFlagSet(ESContentInfo::ES_CONTENT_TYPE_ENCRYPTED);

		if (is_content_encrypted) {
			ESCrypto::SetupContentAesIv(content_[i].GetContentIndex(), content_iv_);
		}

		// write blocks
		for (size_t j = 0; j < (content_[i].GetSize() / kIoBufferLen); j++) {
			WriteContentBlockToFile(content_[i].GetData() + (kIoBufferLen * j), kIoBufferLen, is_content_encrypted, fp);
		}

		// write final unaligned block
		if (content_[i].GetSize() % kIoBufferLen) {
			WriteContentBlockToFile(content_[i].GetData() + ((content_[i].GetSize() / kIoBufferLen) * kIoBufferLen), content_[i].GetSize() % kIoBufferLen, is_content_encrypted, fp);
		}
	}

	// footer
	if (header_.GetFooterSize() > 0) {
		fwrite(padding, header_.GetFooterOffset() - (header_.GetContentOffset() + header_.GetContentSize()), 1, fp);
		fwrite(footer_.GetSerialisedData(), footer_.GetSerialisedDataSize(), 1, fp);
	}
}

void CiaBuilder::WriteToBuffer(MemoryBlob& out)
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
	memcpy(out.data() + header_.GetFooterOffset(), footer_.GetSerialisedData(), footer_.GetSerialisedDataSize());

	u64 pos = header_.GetContentOffset();
	for (size_t i = 0; i < content_.size(); i++) {
		if (content_[i].IsFlagSet(ESContentInfo::ES_CONTENT_TYPE_ENCRYPTED)) {
			ESCrypto::SetupContentAesIv(content_[i].GetContentIndex(), content_iv_);
			Crypto::AesCbcEncrypt(content_[i].GetData(), content_[i].GetSize(), titlekey_, content_iv_, out.data() + pos);
		}
		else {
			memcpy(out.data() + pos, content_[i].GetData(), content_[i].GetSize());
		}


		pos += content_[i].GetSize();
	}
}


void CiaBuilder::SetCaCert(const u8 * cert)
{
	ca_cert_.DeserialiseCert(cert);
}

void CiaBuilder::SetTicketSigner(const Crypto::sRsa2048Key & rsa_key, const u8 * cert)
{
	tik_sign_.cert.DeserialiseCert(cert);
	tik_sign_.rsa_key = rsa_key;
}

void CiaBuilder::SetTmdSigner(const Crypto::sRsa2048Key & rsa_key, const u8 * cert)
{
	tmd_sign_.cert.DeserialiseCert(cert);
	tmd_sign_.rsa_key = rsa_key;
}

void CiaBuilder::AddContent(u32 id, u16 index, u16 flags, const u8* data, u64 size)
{
	ESContent content = ESContent(ESContentInfo(id, index, flags, size, nullptr), data);
	content.UpdateContentHash();

	content_.push_back(content);
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
	SetVersion(ESVersion::make_version(major, minor, build));
}

void CiaBuilder::SetVersion(u16 version)
{
	title_version_ = version;
}

void CiaBuilder::SetFooter(const std::vector<u64>& dependency_list, u64 firmware_title_id, const u8* icon_data, size_t icon_size)
{
	footer_.SetDependencyList(dependency_list);
	footer_.SetFirmwareTitleId(firmware_title_id);
	if (icon_size > 0 && icon_data != NULL)
	{
		footer_.SetIcon(icon_data, icon_size);
	}
	footer_.SerialiseFooter();
}
