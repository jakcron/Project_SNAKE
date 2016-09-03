#include <cstring>
#include "cia_header.h"

CiaHeader::CiaHeader()
{
	ClearDeserialisedVariables();
}

CiaHeader::~CiaHeader()
{
}

const u8* CiaHeader::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t CiaHeader::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void CiaHeader::SerialiseHeader()
{
	// check supported type and version
	if (!IsSupportedType(type_))
	{
		throw ProjectSnakeException(kModuleName, "Unsupported cia type");
	}

	if (!IsSupportedFormatVersion(version_))
	{
		throw ProjectSnakeException(kModuleName, "Unsupported cia format version");
	}

	// check required elements are present
	if (content_.size == 0)
	{
		throw ProjectSnakeException(kModuleName, "Cia has no content");
	}

	// do some additional calculation
	CalculateSectionOffsets();
	CalculateCiaSize();

	// serialise header
	memset((u8*)&header_, 0, sizeof(struct sCiaHeader));
	set_header_size(sizeof(sCiaHeader));
	set_type(type_);
	set_version(version_);
	set_certificate_size(cert_.size);
	set_ticket_size(tik_.size);
	set_title_metadata_size(tmd_.size);
	set_cxi_metadata_size(meta_data_.size);
	set_content_size(content_.size);
	for (u16 index : enabled_content_)
	{
		set_content_index(index);
	}

	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sCiaHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for cia header");
	}

	// copy header into serialised data
	memcpy(serialised_data_.data(), &header_, sizeof(sCiaHeader));
}

void CiaHeader::SetCertificateChainSize(size_t size)
{
	cert_.size = size;
}

void CiaHeader::SetTicketSize(size_t size)
{
	tik_.size = size;
}

void CiaHeader::SetTmdSize(size_t size)
{
	tmd_.size = size;
}

void CiaHeader::SetCxiMetaDataSize(size_t size)
{
	meta_data_.size = size;
}

void CiaHeader::SetContentSize(size_t size)
{
	content_.size = size;
}

void CiaHeader::EnableContent(u16 index)
{
	enabled_content_.push_back(index);
}

void CiaHeader::DeserialiseHeader(const u8* cia_data)
{
	ClearDeserialisedVariables();
	memcpy(&header_, cia_data, sizeof(sCiaHeader));

	// confirm data is likely a cia header
	if (header_size() != sizeof(sCiaHeader))
	{
		throw ProjectSnakeException(kModuleName, "Cia is corrupt");
	}

	// check supported type and version
	if (!IsSupportedType(type()))
	{
		throw ProjectSnakeException(kModuleName, "Cia has unsupported type");
	}

	if (!IsSupportedFormatVersion(version()))
	{
		throw ProjectSnakeException(kModuleName, "Cia has unsupported format version");
	}

	// save local copy of header
	if (serialised_data_.alloc(sizeof(sCiaHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for cia header");
	}
	memcpy(serialised_data_.data(), cia_data, sizeof(sCiaHeader));

	// deserialise header
	type_ = type();
	version_ = version();
	cert_.size = certificate_size();
	tik_.size = ticket_size();
	tmd_.size = title_metadata_size();
	meta_data_.size = cxi_metadata_size();
	content_.size = content_size();
	for (u32 i = 0; i <= 0xffff; i++)
	{
		if (is_content_index_set(i))
		{
			enabled_content_.push_back((u16)i);
		}
	}

	// do further calculations
	CalculateSectionOffsets();
	CalculateCiaSize();
}

size_t CiaHeader::GetCertificateChainOffset() const
{
	return cert_.offset;
}

size_t CiaHeader::GetCertificateChainSize() const
{
	return cert_.size;
}

size_t CiaHeader::GetTicketOffset() const
{
	return tik_.offset;
}

size_t CiaHeader::GetTicketSize() const
{
	return tik_.size;
}

size_t CiaHeader::GetTmdOffset() const
{
	return tmd_.offset;
}

size_t CiaHeader::GetTmdSize() const
{
	return tmd_.size;
}

size_t CiaHeader::GetCxiMetaDataOffset() const
{
	return meta_data_.offset;
}

size_t CiaHeader::GetCxiMetaDataSize() const
{
	return meta_data_.size;
}

size_t CiaHeader::GetContentOffset() const
{
	return content_.offset;
}

size_t CiaHeader::GetContentSize() const
{
	return content_.size;
}

size_t CiaHeader::GetPredictedCiaSize() const
{
	return predicted_cia_size_;
}

bool CiaHeader::IsContentEnabled(u16 index) const
{
	bool is_enabled = false;
	for (u16 enabled_index : enabled_content_)
	{
		if (index == enabled_index)
		{
			is_enabled = true;
			break;
		}
	}
	return is_enabled;
}

const std::vector<u16>& CiaHeader::GetEnabledContentList() const
{
	return enabled_content_;
}

void CiaHeader::CalculateSectionOffsets()
{
	cert_.offset = cert_.size == 0 ? 0 : align(sizeof(sCiaHeader), kCiaSizeAlign);
	tik_.offset = tik_.size == 0 ? 0 : align(sizeof(sCiaHeader), kCiaSizeAlign) \
		+ align(cert_.size, kCiaSizeAlign);
	tmd_.offset = tmd_.size == 0 ? 0 : align(sizeof(sCiaHeader), kCiaSizeAlign) \
		+ align(cert_.size, kCiaSizeAlign) \
		+ align(tik_.size, kCiaSizeAlign);
	content_.offset = content_.size == 0 ? 0 : align(sizeof(sCiaHeader), kCiaSizeAlign) \
		+ align(cert_.size, kCiaSizeAlign) \
		+ align(tik_.size, kCiaSizeAlign) \
		+ align(tmd_.size, kCiaSizeAlign);
	meta_data_.offset = meta_data_.size == 0 ? 0 : align(sizeof(sCiaHeader), kCiaSizeAlign) \
		+ align(cert_.size, kCiaSizeAlign) \
		+ align(tik_.size, kCiaSizeAlign) \
		+ align(tmd_.size, kCiaSizeAlign) \
		+ align(content_.size, kCiaSizeAlign);
}

void CiaHeader::CalculateCiaSize()
{
	predicted_cia_size_ = align(sizeof(sCiaHeader), kCiaSizeAlign) \
		+ align(cert_.size, kCiaSizeAlign) \
		+ align(tik_.size, kCiaSizeAlign) \
		+ align(tmd_.size, kCiaSizeAlign);

	if (meta_data_.size)
	{
		predicted_cia_size_ += align(content_.size, kCiaSizeAlign) + meta_data_.size;
	}
	else
	{
		predicted_cia_size_ += content_.size;
	}
}

bool CiaHeader::IsSupportedType(u16 type)
{
	return type == kCiaType;
}

bool CiaHeader::IsSupportedFormatVersion(u16 version)
{
	return version == kCiaVersion;
}

void CiaHeader::ClearDeserialisedVariables()
{
	type_ = 0;
	version_ = 0;
	cert_.offset = 0;
	cert_.size = 0;
	tik_.offset = 0;
	tik_.size = 0;
	tmd_.offset = 0;
	tmd_.size = 0;
	content_.offset = 0;
	content_.size = 0;
	meta_data_.offset = 0;
	meta_data_.size = 0;
	enabled_content_.clear();
	predicted_cia_size_ = 0;
}
