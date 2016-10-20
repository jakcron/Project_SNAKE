#include "wad_header.h"



WadHeader::WadHeader()
{
}


WadHeader::~WadHeader()
{
}

const u8 * WadHeader::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t WadHeader::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void WadHeader::CalculateSectionOffsets()
{
	certs_.offset = certs_.size == 0 ? 0 : align(sizeof(sWadHeader), kSizeAlign);
	tik_.offset = tik_.size == 0 ? 0 : align(sizeof(sWadHeader), kSizeAlign) \
		+ align(certs_.size, kSizeAlign);
	tmd_.offset = tmd_.size == 0 ? 0 : align(sizeof(sWadHeader), kSizeAlign) \
		+ align(certs_.size, kSizeAlign) \
		+ align(tik_.size, kSizeAlign);
	content_.offset = content_.size == 0 ? 0 : align(sizeof(sWadHeader), kSizeAlign) \
		+ align(certs_.size, kSizeAlign) \
		+ align(tik_.size, kSizeAlign) \
		+ align(tmd_.size, kSizeAlign);
	footer_.offset = footer_.size == 0 ? 0 : align(sizeof(sWadHeader), kSizeAlign) \
		+ align(certs_.size, kSizeAlign) \
		+ align(tik_.size, kSizeAlign) \
		+ align(tmd_.size, kSizeAlign) \
		+ align(content_.size, kSizeAlign);
}

void WadHeader::CalculateWadSize()
{
	predicted_wad_size_ = align(sizeof(sWadHeader), kSizeAlign) \
		+ align(certs_.size, kSizeAlign) \
		+ align(tik_.size, kSizeAlign) \
		+ align(tmd_.size, kSizeAlign);

	if (footer_.size)
	{
		predicted_wad_size_ += align(content_.size, kSizeAlign) + footer_.size;
	}
	else
	{
		predicted_wad_size_ += content_.size;
	}
}

bool WadHeader::IsSupportedType(u16 type)
{
	return type == WAD_TYPE_0 || type == WAD_TYPE_1 || type == WAD_TYPE_2;
}

bool WadHeader::IsSupportedFormatVersion(u16 version)
{
	return version == WAD_VERSION_0;
}

void WadHeader::ClearDeserialisedVariables()
{
	type_ = WAD_TYPE_0;
	version_ = WAD_VERSION_0;
	certs_.offset = 0;
	certs_.size = 0;
	tik_.offset = 0;
	tik_.size = 0;
	tmd_.offset = 0;
	tmd_.size = 0;
	content_.offset = 0;
	content_.size = 0;
	footer_.offset = 0;
	footer_.size = 0;
	predicted_wad_size_ = 0;
}

void WadHeader::DeserialiseHeader(const u8 * wad_data)
{
	ClearDeserialisedVariables();
	memcpy(&header_, wad_data, sizeof(sWadHeader));

	// confirm data is likely a cia header
	if (header_size() != sizeof(sWadHeader))
	{
		throw ProjectSnakeException(kModuleName, "Wad is corrupt");
	}

	// check supported type and version
	if (!IsSupportedType(type()))
	{
		throw ProjectSnakeException(kModuleName, "Wad has unsupported type");
	}

	if (!IsSupportedFormatVersion(version()))
	{
		throw ProjectSnakeException(kModuleName, "Wad has unsupported format version");
	}

	// save local copy of header
	if (serialised_data_.alloc(sizeof(sWadHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for wad header");
	}
	memcpy(serialised_data_.data(), wad_data, sizeof(sWadHeader));

	// deserialise header
	type_ = type();
	version_ = version();
	certs_.size = certificate_size();
	tik_.size = ticket_size();
	tmd_.size = tmd_size();
	content_.size = content_size();
	footer_.size = footer_size();
	

	// do further calculations
	CalculateSectionOffsets();
	CalculateWadSize();
}

size_t WadHeader::GetCertificateChainOffset() const
{
	return certs_.offset;
}

size_t WadHeader::GetCertificateChainSize() const
{
	return certs_.size;
}

size_t WadHeader::GetTicketOffset() const
{
	return tik_.offset;
}

size_t WadHeader::GetTicketSize() const
{
	return tik_.size;
}

size_t WadHeader::GetTmdOffset() const
{
	return tmd_.offset;
}

size_t WadHeader::GetTmdSize() const
{
	return tmd_.size;
}

size_t WadHeader::GetContentOffset() const
{
	return content_.offset;
}

size_t WadHeader::GetContentSize() const
{
	return content_.size;
}

size_t WadHeader::GetFooterOffset() const
{
	return footer_.offset;
}

size_t WadHeader::GetFooterSize() const
{
	return footer_.size;
}

size_t WadHeader::GetPredictedWadSize() const
{
	return predicted_wad_size_;
}

void WadHeader::SerialiseHeader()
{
	// check supported type and version
	if (!IsSupportedType(type_))
	{
		throw ProjectSnakeException(kModuleName, "Unsupported wad type");
	}

	if (!IsSupportedFormatVersion(version_))
	{
		throw ProjectSnakeException(kModuleName, "Unsupported wad format version");
	}

	// check required elements are present
	if (content_.size == 0)
	{
		throw ProjectSnakeException(kModuleName, "Wad has no content");
	}

	// do some additional calculation
	CalculateSectionOffsets();
	CalculateWadSize();

	// serialise header
	memset((u8*)&header_, 0, sizeof(sWadHeader));
	set_header_size(sizeof(sWadHeader));
	set_type(type_);
	set_version(version_);
	set_certificate_size(certs_.size);
	set_ticket_size(tik_.size);
	set_tmd_size(tmd_.size);
	set_content_size(content_.size);
	set_footer_size(footer_.size);

	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sWadHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for wad header");
	}

	// copy header into serialised data
	memcpy(serialised_data_.data(), &header_, sizeof(sWadHeader));
}

void WadHeader::SetCertificateChainSize(size_t size)
{
	certs_.size;
}

void WadHeader::SetTicketSize(size_t size)
{
	tik_.size;
}

void WadHeader::SetTmdSize(size_t size)
{
	tmd_.size = size;
}

void WadHeader::SetContentSize(size_t size)
{
	content_.size = size;
}

void WadHeader::SetFooterSize(size_t size)
{
	footer_.size = size;
}
