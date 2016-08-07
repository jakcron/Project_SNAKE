#include <cstring>
#include "cia_header.h"

CiaHeader::CiaHeader()
{
	memset((u8*)&header_, 0, sizeof(struct sCiaHeader));
}

CiaHeader::~CiaHeader()
{
}

int CiaHeader::CreateCiaHeader()
{
	header_.header_size = sizeof(struct sCiaHeader);
	header_.type = kCiaType;
	header_.version = kCiaVersion;

	return 0;
}

void CiaHeader::SetCertificateSize(u32 size)
{
	header_.certificate_size = le_word(size);
}

void CiaHeader::SetTicketSize(u32 size)
{
	header_.ticket_size = le_word(size);
}

void CiaHeader::SetTmdSize(u32 size)
{
	header_.title_metadata_size = le_word(size);
}

void CiaHeader::SetMetaSize(u32 size)
{
	header_.cxi_metadata_size = le_word(size);
}

void CiaHeader::SetContentSize(u64 size)
{
	header_.content_total_size = le_dword(size);
}

void CiaHeader::SetContentMask(const std::vector<u16>& indexes)
{
	for (size_t i = 0; i < indexes.size(); i++)
	{
		header_.content_mask[indexes[i] / 8] |= BIT(7 - (indexes[i] % 8));
	}
}
