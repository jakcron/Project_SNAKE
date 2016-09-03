#include "cia_cxi_meta_data.h"



CiaCxiMetaData::CiaCxiMetaData()
{
	ClearDeserialisedVariables();
}


CiaCxiMetaData::~CiaCxiMetaData()
{
}

const u8 * CiaCxiMetaData::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t CiaCxiMetaData::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void CiaCxiMetaData::SerialiseMetaData()
{
	size_t data_size = sizeof(sMetaDataBody) + icon_.size();
	if (serialised_data_.alloc(data_size) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for cxi meta data");
	}
	
	// serialise body
	for (int i = 0; i < kMaxDependencyNum && i < dependency_list_.size(); i++)
	{
		set_dependency_title_id(i, dependency_list_[i]);
	}
	set_firmware_title_id(firm_title_id_);

	// copy body into serialised data
	memcpy(serialised_data_.data(), &body_, sizeof(sMetaDataBody));

	// copy icon, if it exists
	if (icon_.size())
	{
		memcpy(serialised_data_.data() + sizeof(sMetaDataBody), icon_.data_const(), icon_.size());
	}
}

void CiaCxiMetaData::SetDependencyList(const std::vector<u64>& dependency_list)
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

void CiaCxiMetaData::SetFirmwareTitleId(u64 title_id)
{
	firm_title_id_ = title_id;
}

void CiaCxiMetaData::SetIcon(const u8* data, size_t size)
{
	if (icon_.alloc(size) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for icon");
	}

	memcpy(icon_.data(), data, size);
}

void CiaCxiMetaData::DeserialiseMetaData(const u8* data, size_t size)
{
	ClearDeserialisedVariables();
	// check required size
	if (size < sizeof(sMetaDataBody))
	{
		throw ProjectSnakeException(kModuleName, "Cxi meta data is corrupt");
	}
	memcpy(&body_, data, sizeof(sMetaDataBody));

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
	for (int i = 0; i < kMaxDependencyNum && dependency_title_id(i) != 0; i++)
	{
		dependency_list_.push_back(dependency_title_id(i));
	}
	firm_title_id_ = firmware_title_id();

	// save icon
	if (serialised_data_.size() > sizeof(sMetaDataBody))
	{
		size_t icon_size = serialised_data_.size() - sizeof(sMetaDataBody);
		SetIcon(serialised_data_.data_const() + sizeof(sMetaDataBody), icon_size);
	}
}

const std::vector<u64>& CiaCxiMetaData::GetDependencyList() const
{
	return dependency_list_;
}

u64 CiaCxiMetaData::GetFirmwareTitleId() const
{
	return firm_title_id_;
}

const u8 * CiaCxiMetaData::GetIcon() const
{
	return icon_.data_const();
}

size_t CiaCxiMetaData::GetIconSize() const
{
	return icon_.size();
}

void CiaCxiMetaData::ClearDeserialisedVariables()
{
	dependency_list_.clear();
	firm_title_id_ = 0;
	icon_.alloc(0);
}
