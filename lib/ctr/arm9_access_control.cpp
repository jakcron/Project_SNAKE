#include "arm9_access_control.h"



Arm9AccessControl::Arm9AccessControl()
{
	ClearDeserialisedVariables();
}

Arm9AccessControl::Arm9AccessControl(const u8 * data)
{
	DeserialiseData(data);
}

Arm9AccessControl::Arm9AccessControl(const Arm9AccessControl & other)
{
	DeserialiseData(other.GetSerialisedData());
}


Arm9AccessControl::~Arm9AccessControl()
{
}

void Arm9AccessControl::operator=(const Arm9AccessControl & other)
{
	DeserialiseData(other.GetSerialisedData());
}

const u8 * Arm9AccessControl::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t Arm9AccessControl::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void Arm9AccessControl::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sArm9AccessControl)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	sArm9AccessControl* arm9 = (sArm9AccessControl*)serialised_data_.data();

	for (size_t i = 0; i < io_rights_.size(); i++)
	{
		arm9->set_io_right(io_rights_[i], true);
	}

	arm9->set_desc_version(desc_version_);
}

void Arm9AccessControl::SetIORights(const std::vector<IORight>& rights)
{
	io_rights_.clear();
	for (size_t i = 0; i < rights.size(); i++)
	{
		io_rights_.push_back(rights[i]);
	}
}

void Arm9AccessControl::SetDescVersion(u8 version)
{
	desc_version_ = version;
}

void Arm9AccessControl::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();

	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sArm9AccessControl)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	memcpy(serialised_data_.data(), data, sizeof(sArm9AccessControl));

	const sArm9AccessControl* arm9 = (const sArm9AccessControl*)serialised_data_.data_const();

	for (u32 i = 0; i < kMaxIOFlags; i++)
	{
		if (arm9->has_io_right((IORight)i))
		{
			io_rights_.push_back((IORight)i);
		}
	}

	desc_version_ = arm9->desc_version();
}

const std::vector<Arm9AccessControl::IORight>& Arm9AccessControl::GetIORights() const
{
	return io_rights_;
}

u8 Arm9AccessControl::GetDescVersion() const
{
	return desc_version_;
}

void Arm9AccessControl::ClearDeserialisedVariables()
{
	io_rights_.clear();
	desc_version_ = 0;
}
