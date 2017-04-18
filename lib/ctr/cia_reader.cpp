#include "cia_reader.h"
#include "ctr_program_id.h"
#include "ctr_tmd_reserved_data.h"



CiaReader::CiaReader()
{
}


CiaReader::~CiaReader()
{
}

void CiaReader::ImportCia(const u8 * cia_data)
{
	// get header
	header_.DeserialiseHeader(cia_data);

	// check more sections? remove legacy support for older formats?
	if (header_.GetContentSize() == 0)
	{
		throw ProjectSnakeException(kModuleName, "Cia has no content");
	}

	// get sections
	if (header_.GetCertificateChainSize() > 0)
	{
		certs_.DeserialiseCertChain(cia_data + header_.GetCertificateChainOffset(), header_.GetCertificateChainSize());
	}

	if (header_.GetTicketSize() > 0)
	{
		tik_.DeserialiseTicket(cia_data + header_.GetTicketOffset(), header_.GetTicketSize());
	}

	if (header_.GetTmdSize() > 0)
	{
		tmd_.DeserialiseTmd(cia_data + header_.GetTmdOffset(), header_.GetTmdSize());

		DeserialiseTmdPlatformReservedData();
	}

	if (header_.GetFooterSize() > 0)
	{
		footer_.DeserialiseFooter(cia_data + header_.GetFooterOffset(), header_.GetFooterSize());
	}

	// corruption check
	if (tmd_.GetTitleId() != tik_.GetTitleId())
	{
		throw ProjectSnakeException(kModuleName, "Cia is corrupt, ticket and tmd have mismatching title ids");
	}

	// save info about
	size_t content_pos = 0;
	for (const auto& tmd_content : tmd_.GetContentList())
	{
		ESContent content = ESContent(tmd_content, cia_data + header_.GetContentOffset() + content_pos);
		
		// enable content
		content.EnableContent(tik_.IsContentEnabled(content.GetContentIndex()));
		
		// note related data
		if (header_.IsContentEnabled(content.GetContentIndex()) != tik_.IsContentEnabled(content.GetContentIndex()))
		{
			throw ProjectSnakeException(kModuleName, "Cia content enabled inconsistient between ticket and cia header");
		}
		// add to list
		content_list_.push_back(content);

		// increment pos
		content_pos += align(content.GetSize(), 0x10);
	}
}

u64 CiaReader::GetTitleId() const
{
	return tmd_.GetTitleId();
}

u16 CiaReader::GetTitleVersion() const
{
	return tmd_.GetTitleVersion();
}

u8 CiaReader::GetCommonKeyIndex() const
{
	return tik_.GetCommonKeyIndex();
}

u32 CiaReader::GetCtrSaveSize() const
{
	return ctr_save_size_;
}

u32 CiaReader::GetTwlPublicSaveSize() const
{
	return twl_public_save_size_;
}

u32 CiaReader::GetTwlPrivateSaveSize() const
{
	return twl_private_save_size_;
}

u8 CiaReader::GetSrlFlag() const
{
	return srl_flag_;
}

const u8 * CiaReader::GetTitleKey(const u8 * common_key)
{
	return tik_.GetTitleKey(common_key);
}

const ESCertChain & CiaReader::GetCertificateChain() const
{
	return certs_;
}

const ESTicket & CiaReader::GetTicket() const
{
	return tik_;
}

const ESTmd & CiaReader::GetTmd() const
{
	return tmd_;
}

const CiaFooter & CiaReader::GetFooter() const
{
	return footer_;
}

std::vector<ESContent>& CiaReader::GetContentList()
{
	return content_list_;
}

bool CiaReader::ValidateCertificates(const Crypto::sRsa4096Key & root_key) const
{
	return certs_.ValidateChain(root_key);
}

bool CiaReader::ValidateCertificatesExceptCa() const
{
	return certs_.ValidateChainExceptCa();
}

bool CiaReader::ValidateTicket() const
{
	return tik_.ValidateSignature(certs_[tik_.GetIssuer()]);
}

bool CiaReader::ValidateTmd() const
{
	return tmd_.ValidateSignature(certs_[tmd_.GetIssuer()]);
}

void CiaReader::DeserialiseTmdPlatformReservedData()
{
	// deserialise platform reserved region
	const sCtrTmdPlatormReservedRegion* tmd_data = (const sCtrTmdPlatormReservedRegion*)tmd_.GetPlatformReservedData();

	// TWL title
	if ((CtrProgramId::get_category(tmd_.GetTitleId()) & CtrProgramId::CATEGORY_FLAG_TWL_TITLE) == CtrProgramId::CATEGORY_FLAG_TWL_TITLE)
	{

		twl_public_save_size_ = tmd_data->public_save_data_size();
		twl_private_save_size_ = tmd_data->private_save_data_size();
		srl_flag_ = tmd_data->srl_flag();

		ctr_save_size_ = 0;
	}
	// CTR title
	else
	{
		ctr_save_size_ = tmd_data->public_save_data_size();

		twl_public_save_size_ = 0;
		twl_private_save_size_ = 0;
		srl_flag_ = 0;
	}
}
