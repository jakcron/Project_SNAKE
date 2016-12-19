#include "extended_header.h"



ExtendedHeader::ExtendedHeader() :
	system_control_info_(),
	arm11_local_caps_(),
	arm11_kernel_caps_(),
	arm9_access_control_()
{
}

ExtendedHeader::ExtendedHeader(const u8 * data)
{
	DeserialiseData(data);
}

ExtendedHeader::ExtendedHeader(const ExtendedHeader & other)
{
	DeserialiseData(other.GetSerialisedData());
}


ExtendedHeader::ExtendedHeader(const SystemControlInfo & system, const Arm11LocalCaps & arm11_local, const Arm11KernelCaps & arm11_kernel, const Arm9AccessControl & arm9) :
	system_control_info_(system),
	arm11_local_caps_(arm11_local),
	arm11_kernel_caps_(arm11_kernel),
	arm9_access_control_(arm9)
{
	SerialiseData();
}

ExtendedHeader::~ExtendedHeader()
{
}

void ExtendedHeader::operator=(const ExtendedHeader & other)
{
	DeserialiseData(other.GetSerialisedData());
}

const u8 * ExtendedHeader::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t ExtendedHeader::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void ExtendedHeader::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sExtendedHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	sExtendedHeader* exhdr = (sExtendedHeader*)serialised_data_.data();

	system_control_info_.SerialiseData();
	memcpy(exhdr->system_control_info, system_control_info_.GetSerialisedData(), kSystemControlInfoSize);

	arm11_local_caps_.SerialiseData();
	memcpy(exhdr->arm11_local_caps, arm11_local_caps_.GetSerialisedData(), kArm11LocalCapsSize);

	arm11_kernel_caps_.SerialiseData();
	memcpy(exhdr->arm11_kernel_caps, arm11_kernel_caps_.GetSerialisedData(), kArm11KernelCapsSize);

	arm9_access_control_.SerialiseData();
	memcpy(exhdr->arm9_access_control, arm9_access_control_.GetSerialisedData(), kArm9AccessControlSize);
}

void ExtendedHeader::SetSystemControlInfo(const SystemControlInfo & system)
{
	system_control_info_ = system;
}

void ExtendedHeader::SetArm11LocalCaps(const Arm11LocalCaps & arm11_local)
{
	arm11_local_caps_ = arm11_local;
}

void ExtendedHeader::SetArm11KernelCaps(const Arm11KernelCaps & arm11_kernel)
{
	arm11_kernel_caps_ = arm11_kernel;
}

void ExtendedHeader::SetArm9AccessControl(const Arm9AccessControl & arm9)
{
	arm9_access_control_ = arm9;
}

void ExtendedHeader::DeserialiseData(const u8 * data)
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sExtendedHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	memcpy(serialised_data_.data(), data, sizeof(sExtendedHeader));

	const sExtendedHeader* exhdr = (const sExtendedHeader*)serialised_data_.data_const();

	system_control_info_.DeserialiseData(exhdr->system_control_info);
	arm11_local_caps_.DeserialiseData(exhdr->arm11_local_caps);
	arm11_kernel_caps_.DeserialiseData(exhdr->arm11_kernel_caps);
	arm9_access_control_.DeserialiseData(exhdr->arm9_access_control);
}

const SystemControlInfo & ExtendedHeader::GetSystemControlInfo() const
{
	return system_control_info_;
}

const Arm11LocalCaps & ExtendedHeader::GetArm11LocalCaps() const
{
	return arm11_local_caps_;
}

const Arm11KernelCaps & ExtendedHeader::GetArm11KernelCaps() const
{
	return arm11_kernel_caps_;
}

const Arm9AccessControl & ExtendedHeader::GetArm9AccessControl() const
{
	return arm9_access_control_;
}
