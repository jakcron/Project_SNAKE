#include "cia_footer.h"



CiaFooter::CiaFooter()
{
	ClearDeserialisedVariables();
}


CiaFooter::~CiaFooter()
{
}

const u8 * CiaFooter::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t CiaFooter::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void CiaFooter::SerialiseFooter()
{
	size_t data_size = sizeof(sCiaFooterBody) + icon_.size();
	if (serialised_data_.alloc(data_size) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for cxi meta data");
	}
	
	// serialise body
	for (size_t i = 0; i < kMaxDependencyNum && i < dependency_list_.size(); i++)
	{
		set_dependency_title_id(i, dependency_list_[i]);
	}
	set_firmware_title_id(firm_title_id_);

	// copy body into serialised data
	memcpy(serialised_data_.data(), &body_, sizeof(sCiaFooterBody));

	// copy icon, if it exists
	if (icon_.size())
	{
		memcpy(serialised_data_.data() + sizeof(sCiaFooterBody), icon_.data_const(), icon_.size());
	}
}

void CiaFooter::SetDependencyList(const std::vector<u64>& dependency_list)
{
	if (dependency_list.size() > kMaxDependencyNum)
	{
		throw ProjectSnakeException(kModuleName, "Too many dependencies");
	}

	for (u64 title_id : dependency_list)
	{
		dependency_list_.push_back(title_id);
	}
}

void CiaFooter::SetFirmwareTitleId(u64 title_id)
{
	firm_title_id_ = title_id;
}

void CiaFooter::SetIcon(const u8* data, size_t size)
{
	if (icon_.alloc(size) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for icon");
	}

	memcpy(icon_.data(), data, size);
}

void CiaFooter::DeserialiseFooter(const u8* data, size_t size)
{
	ClearDeserialisedVariables();
	// check required size
	if (size < sizeof(sCiaFooterBody))
	{
		throw ProjectSnakeException(kModuleName, "Cxi meta data is corrupt");
	}
	memcpy(&body_, data, sizeof(sCiaFooterBody));

	// if there are dependencies, they will have the category MODULE, otherwise this is likely corrupt
	if (dependency_title_id(0) != 0 && ProgramId::get_category(dependency_title_id(0)) != ProgramId::CATEGORY_MODULE)
	{
		throw ProjectSnakeException(kModuleName, "Cxi meta data is corrupt");
	}

	// save local copy of serialised data
	if (serialised_data_.alloc(size) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for cxi meta data");
	}
	memcpy(serialised_data_.data(), data, size);

	// deserialise body
	for (size_t i = 0; i < kMaxDependencyNum && dependency_title_id(i) != 0; i++)
	{
		dependency_list_.push_back(dependency_title_id(i));
	}
	firm_title_id_ = firmware_title_id();

	// save icon
	if (serialised_data_.size() > sizeof(sCiaFooterBody))
	{
		size_t icon_size = serialised_data_.size() - sizeof(sCiaFooterBody);
		SetIcon(serialised_data_.data_const() + sizeof(sCiaFooterBody), icon_size);
	}
}

const std::vector<u64>& CiaFooter::GetDependencyList() const
{
	return dependency_list_;
}

u64 CiaFooter::GetFirmwareTitleId() const
{
	return firm_title_id_;
}

const u8 * CiaFooter::GetIcon() const
{
	return icon_.data_const();
}

size_t CiaFooter::GetIconSize() const
{
	return icon_.size();
}

void CiaFooter::ClearDeserialisedVariables()
{
	dependency_list_.clear();
	firm_title_id_ = 0;
	icon_.alloc(0);
}
