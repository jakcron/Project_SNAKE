#include "access_descriptor.h"



AccessDescriptor::AccessDescriptor()
{
	ClearDeserialisedVariables();
}

AccessDescriptor::AccessDescriptor(const u8 * data)
{
	DeserialiseData(data);
}


AccessDescriptor::AccessDescriptor(const AccessDescriptor & other)
{
	DeserialiseData(other.GetSerialisedData());
}

AccessDescriptor::~AccessDescriptor()
{
}

void AccessDescriptor::operator=(const AccessDescriptor & other)
{
	DeserialiseData(other.GetSerialisedData());
}

const u8 * AccessDescriptor::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t AccessDescriptor::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void AccessDescriptor::SerialiseData(const Crypto::sRsa2048Key & accessdesc_rsa_key)
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sAccessDescriptor)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	sAccessDescriptor* desc = (sAccessDescriptor*)serialised_data_.data();

	// Serialise & Copy
	memcpy(desc->body.ncch_rsa_public_key, ncch_public_key_.modulus, Crypto::kRsa2048Size);

	arm11_local_caps_.SerialiseData();
	memcpy(desc->body.arm11_local_caps, arm11_local_caps_.GetSerialisedData(), kArm11LocalCapsSize);

	arm11_kernel_caps_.SerialiseData();
	memcpy(desc->body.arm11_kernel_caps, arm11_kernel_caps_.GetSerialisedData(), kArm11KernelCapsSize);

	arm9_access_control_.SerialiseData();
	memcpy(desc->body.arm9_access_control, arm9_access_control_.GetSerialisedData(), kArm9AccessControlSize);

	// Sign Data
	u8 hash[Crypto::kSha256HashLen];
	Crypto::Sha256((const u8*)&desc->body, sizeof(sAccessDescriptor::sBody), hash);

	Crypto::RsaSign(accessdesc_rsa_key, Crypto::HASH_SHA256, hash, desc->rsa_signature);
}

void AccessDescriptor::SetDataUsingExtendedheader(const ExtendedHeader & exheader)
{
	arm11_local_caps_ = Arm11LocalCaps();
	arm11_local_caps_.SetProgramId(exheader.GetArm11LocalCaps().GetProgramId());
	arm11_local_caps_.SetFirmTitleId(exheader.GetArm11LocalCaps().GetFirmTitleId());
	arm11_local_caps_.EnableL2Cache(exheader.GetArm11LocalCaps().IsL2CacheEnabled());
	arm11_local_caps_.SetCpuSpeed(exheader.GetArm11LocalCaps().GetCpuSpeed());
	arm11_local_caps_.SetSystemModeExt(exheader.GetArm11LocalCaps().GetSystemModeExt());
	arm11_local_caps_.SetIdealProcessor(1 << exheader.GetArm11LocalCaps().GetIdealProcessor());
	arm11_local_caps_.SetAffinityMask(exheader.GetArm11LocalCaps().GetAffinityMask());
	arm11_local_caps_.SetSystemMode(exheader.GetArm11LocalCaps().GetSystemMode());
	arm11_local_caps_.SetThreadPriority(exheader.GetArm11LocalCaps().GetThreadPriority()); // check
	arm11_local_caps_.SetSystemSaveIds(exheader.GetArm11LocalCaps().GetSystemSaveId1(), exheader.GetArm11LocalCaps().GetSystemSaveId2());
	arm11_local_caps_.SetFsRights(exheader.GetArm11LocalCaps().GetFsRightList());
	arm11_local_caps_.SetServiceACL(exheader.GetArm11LocalCaps().GetServiceACL());

	arm11_kernel_caps_ = exheader.GetArm11KernelCaps();
	arm9_access_control_ = exheader.GetArm9AccessControl();
}

void AccessDescriptor::SetNcchRsaKey(const Crypto::sRsa2048Key & rsa_key)
{
	ncch_public_key_ = rsa_key;
}

void AccessDescriptor::SetArm11LocalCaps(const Arm11LocalCaps & arm11_local)
{
	arm11_local_caps_ = arm11_local;
}

void AccessDescriptor::SetArm11KernelCaps(const Arm11KernelCaps & arm11_kernel)
{
	arm11_kernel_caps_ = arm11_kernel;
}

void AccessDescriptor::SetArm9AccessControl(const Arm9AccessControl & arm9)
{
	arm9_access_control_ = arm9;
}


void AccessDescriptor::DeserialiseData(const u8 * data)
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sAccessDescriptor)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	memcpy(serialised_data_.data(), data, sizeof(sAccessDescriptor));

	const sAccessDescriptor* desc = (const sAccessDescriptor*)serialised_data_.data_const();

	memcpy(ncch_public_key_.modulus, desc->body.ncch_rsa_public_key, Crypto::kRsa2048Size);
	arm11_local_caps_.DeserialiseData(desc->body.arm11_local_caps);
	arm11_kernel_caps_.DeserialiseData(desc->body.arm11_kernel_caps);
	arm9_access_control_.DeserialiseData(desc->body.arm9_access_control);
}

bool AccessDescriptor::ValidateSignature(const Crypto::sRsa2048Key & accessdesc_rsa_key) const
{
	const sAccessDescriptor* data = (const sAccessDescriptor*)serialised_data_.data_const();

	// hash header
	u8 hash[Crypto::kSha256HashLen];
	Crypto::Sha256((const u8*)&data->body, sizeof(sAccessDescriptor::sBody), hash);

	// verify signature	
	return Crypto::RsaVerify(accessdesc_rsa_key, Crypto::HASH_SHA256, hash, data->rsa_signature) == 0;
}

const Crypto::sRsa2048Key & AccessDescriptor::GetNcchRsaKey() const
{
	return ncch_public_key_;
}

const Arm11LocalCaps & AccessDescriptor::GetArm11LocalCaps() const
{
	return arm11_local_caps_;
}

const Arm11KernelCaps & AccessDescriptor::GetArm11KernelCaps() const
{
	return arm11_kernel_caps_;
}

const Arm9AccessControl & AccessDescriptor::GetArm9AccessControl() const
{
	return arm9_access_control_;
}

void AccessDescriptor::ValidateExtendedHeader(const ExtendedHeader & exheader)
{
	valid_at_all_ = true;
	CheckProgramId(exheader.GetArm11LocalCaps().GetProgramId());
	CheckFirmwareTitleId(exheader.GetArm11LocalCaps().GetFirmTitleId());
	CheckEnableL2Cache(exheader.GetArm11LocalCaps().IsL2CacheEnabled());
	CheckCpuSpeed(exheader.GetArm11LocalCaps().GetCpuSpeed());
	CheckSystemModeExt(exheader.GetArm11LocalCaps().GetSystemModeExt());
	CheckIdealProcessor(exheader.GetArm11LocalCaps().GetIdealProcessor());
	CheckAffinityMask(exheader.GetArm11LocalCaps().GetAffinityMask());
	CheckSystemMode(exheader.GetArm11LocalCaps().GetSystemMode());
	CheckThreadPriority(exheader.GetArm11LocalCaps().GetThreadPriority());
	CheckSystemSaveIds(exheader.GetArm11LocalCaps().GetSystemSaveId1(), exheader.GetArm11LocalCaps().GetSystemSaveId2());
	CheckFsRights(exheader.GetArm11LocalCaps().GetFsRightList());
	CheckServiceACL(exheader.GetArm11LocalCaps().GetServiceACL());
	
	CheckSystemCallACL(exheader.GetArm11KernelCaps().GetSystemCallACL());
	CheckInterruptListACL(exheader.GetArm11KernelCaps().GetInterruptACL());
	CheckHandleTableSize(exheader.GetArm11KernelCaps().GetHandleTableSize());
	CheckKernelFlags(exheader.GetArm11KernelCaps().GetKernelFlagList());
	CheckMemoryType(exheader.GetArm11KernelCaps().GetMemoryType());
	
	CheckMemoryMapping(exheader.GetArm11KernelCaps().GetMemoryMapping());
	CheckIORegisterMapping(exheader.GetArm11KernelCaps().GetIORegisterMapping());
	
	CheckIORights(exheader.GetArm9AccessControl().GetIORights());
	CheckDescVersion(exheader.GetArm9AccessControl().GetDescVersion());
	
}

bool AccessDescriptor::IsExheaderValid() const
{
	return valid_at_all_;
}

bool AccessDescriptor::IsProgramIdValid() const
{
	return valid_program_id_;
}

bool AccessDescriptor::IsFirmwareTitleIdValid() const
{
	return valid_firmware_id_;
}

bool AccessDescriptor::IsEnableL2CacheValid() const
{
	return valid_l2_cache_state_;
}

bool AccessDescriptor::IsCpuSpeedValid() const
{
	return valid_cpu_speed_;
}

bool AccessDescriptor::IsSystemModeExtValid() const
{
	return valid_system_mode_ext_;
}

bool AccessDescriptor::IsIdealProcessorValid() const
{
	return valid_ideal_processor_;
}

bool AccessDescriptor::IsAffinityMaskValid() const
{
	return valid_affinity_mask_;
}

bool AccessDescriptor::IsSystemModeValid() const
{
	return valid_system_mode_;
}

bool AccessDescriptor::IsThreadPriorityValid() const
{
	return valid_thread_priority_;
}

bool AccessDescriptor::IsSystemSaveId1Valid() const
{
	return valid_system_save_id_[0];
}

bool AccessDescriptor::IsSystemSaveId2Valid() const
{
	return valid_system_save_id_[1];
}

bool AccessDescriptor::IsFsRightsValid() const
{
	return valid_fs_rights_;
}

bool AccessDescriptor::IsServiceACLValid() const
{
	return valid_service_acl_;
}

bool AccessDescriptor::IsInterruptACLValid() const
{
	return valid_interrupt_acl_;
}

bool AccessDescriptor::IsSystemCallACLValid() const
{
	return valid_system_call_acl_;
}

bool AccessDescriptor::IsHandleTableSizeValid() const
{
	return valid_handle_table_size_;
}

bool AccessDescriptor::IsKernelFlagsValid() const
{
	return valid_kernel_flags_;
}

bool AccessDescriptor::IsMemoryTypeValid() const
{
	return valid_memory_type_;
}

bool AccessDescriptor::IsMemoryMappingValid() const
{
	return valid_memory_mapping_;
}

bool AccessDescriptor::IsIORegisterMappingValid() const
{
	return valid_io_register_mapping_;
}

bool AccessDescriptor::IsIORightsValid() const
{
	return valid_io_rights_;
}

bool AccessDescriptor::IsDescVersionValid() const
{
	return valid_desc_version_;
}

bool AccessDescriptor::CheckMapInRange(const Arm11KernelCaps::sMemoryMapping & map, const Arm11KernelCaps::sMemoryMapping & range)
{
	bool in_range = false;
	if (map.end == range.end && map.end == 0)
	{
		in_range = map.start == range.start && map.read_only == range.read_only;
	}
	else
	{
		in_range = map.start >= range.start && map.start < range.end && map.end <= range.end && map.end > range.start && map.read_only == range.read_only;
	}
	return in_range;
}

void AccessDescriptor::CheckMappingRangeWhiteList(const std::vector<Arm11KernelCaps::sMemoryMapping>& maps, const std::vector<Arm11KernelCaps::sMemoryMapping>& white_list, bool & is_valid)
{
	for (size_t i = 0; i < maps.size(); i++)
	{
		bool found = false;
		for (size_t j = 0; j < white_list.size() && found == false; j++)
		{
			found = CheckMapInRange(maps[i], white_list[j]);
		}

		if (found == false)
		{
			valid_at_all_ = false;
			is_valid = false;
			break;
		}
	}
}

void AccessDescriptor::CheckProgramId(u64 program_id)
{
	u64 desc_program_id = arm11_local_caps_.GetProgramId();

	valid_program_id_ = true;

	for (size_t i = 0; i < sizeof(u64) / 4; i++)
	{
		u8 desc = (desc_program_id >> (i * 4)) & 0xf;
		u8 check = (program_id >> (i * 4)) & 0xf;
		if (desc != check && desc != 0xf)
		{
			valid_at_all_ = false;
			valid_program_id_ = false;
		}
	}
}

void AccessDescriptor::CheckFirmwareTitleId(u64 title_id)
{
	valid_firmware_id_ = true;
	if (arm11_local_caps_.GetFirmTitleId() != title_id)
	{
		valid_at_all_ = false;
		valid_firmware_id_ = false;
	}
}

void AccessDescriptor::CheckEnableL2Cache(bool is_enabled)
{
	valid_l2_cache_state_ = true;
	if (!arm11_local_caps_.IsL2CacheEnabled() && is_enabled)
	{
		valid_at_all_ = false;
		valid_l2_cache_state_ = false;
	}
}

void AccessDescriptor::CheckCpuSpeed(Arm11LocalCaps::CpuSpeed cpu_speed)
{
	valid_cpu_speed_ = true;
	if (cpu_speed > arm11_local_caps_.GetCpuSpeed())
	{
		valid_at_all_ = false;
		valid_cpu_speed_ = false;
	}
}

void AccessDescriptor::CheckSystemModeExt(Arm11LocalCaps::SystemModeExt system_mode)
{
	valid_system_mode_ext_ = true;
	if (system_mode != arm11_local_caps_.GetSystemModeExt())
	{
		valid_at_all_ = false;
		valid_system_mode_ext_ = false;
	}
}

void AccessDescriptor::CheckIdealProcessor(u8 ideal_processor)
{ 
	valid_ideal_processor_ = true;
	if (((1 << ideal_processor) & arm11_local_caps_.GetIdealProcessor()) == 0)
	{
		valid_at_all_ = false;
		valid_ideal_processor_ = false;
	}
}

void AccessDescriptor::CheckAffinityMask(u8 affinity_mask)
{
	valid_affinity_mask_ = true;
	if (affinity_mask & ~(arm11_local_caps_.GetAffinityMask()))
	{
		valid_at_all_ = false;
		valid_affinity_mask_ = false;
	}
}

void AccessDescriptor::CheckSystemMode(Arm11LocalCaps::SystemMode system_mode)
{
	valid_system_mode_ = true;
	if (system_mode != arm11_local_caps_.GetSystemMode())
	{
		valid_at_all_ = false;
		valid_system_mode_ = false;
	}
}

void AccessDescriptor::CheckThreadPriority(int8_t priority)
{
	if (priority >= arm11_local_caps_.GetThreadPriority() && priority < 127)
	{
		valid_thread_priority_ = true;
	}
	else
	{
		valid_at_all_ = false;
		valid_thread_priority_ = false;
	}
}

void AccessDescriptor::CheckSystemSaveIds(u32 id1, u32 id2)
{
	if ((id1 & arm11_local_caps_.GetSystemSaveId1()) == id1)
	{
		valid_system_save_id_[0] = true;
	}
	else
	{
		valid_at_all_ = false;
		valid_system_save_id_[0] = false;
	}

	if ((id2 & arm11_local_caps_.GetSystemSaveId2()) == id2)
	{
		valid_system_save_id_[1] = true;
	}
	else
	{
		valid_at_all_ = false;
		valid_system_save_id_[1] = false;
	}
}

void AccessDescriptor::CheckFsRights(const std::vector<Arm11LocalCaps::FSRight>& right_list)
{
	CheckWhiteList<Arm11LocalCaps::FSRight>(right_list, arm11_local_caps_.GetFsRightList(), valid_fs_rights_);
}

void AccessDescriptor::CheckServiceACL(const std::vector<std::string>& service_list)
{
	CheckWhiteList<std::string>(service_list, arm11_local_caps_.GetServiceACL(), valid_service_acl_);
}

void AccessDescriptor::CheckSystemCallACL(const std::vector<u8>& system_call_list)
{
	CheckWhiteList<u8>(system_call_list, arm11_kernel_caps_.GetSystemCallACL(), valid_system_call_acl_);
}

void AccessDescriptor::CheckInterruptListACL(const std::vector<u8>& interrupt_list)
{
	CheckWhiteList<u8>(interrupt_list, arm11_kernel_caps_.GetInterruptACL(), valid_interrupt_acl_);
}

void AccessDescriptor::CheckHandleTableSize(u32 size)
{
	valid_handle_table_size_ = true;
	if (size > arm11_kernel_caps_.GetHandleTableSize())
	{
		valid_at_all_ = false;
		valid_handle_table_size_ = false;
	}
}

void AccessDescriptor::CheckKernelFlags(const std::vector<Arm11KernelCaps::KernelFlag>& flags)
{
	CheckWhiteList<Arm11KernelCaps::KernelFlag>(flags, arm11_kernel_caps_.GetKernelFlagList(), valid_kernel_flags_);
}

void AccessDescriptor::CheckMemoryType(Arm11KernelCaps::MemoryType memory_type)
{
	valid_memory_type_ = true;
	if (memory_type != arm11_kernel_caps_.GetMemoryType())
	{
		valid_at_all_ = false;
		valid_memory_type_ = false;
	}
}

void AccessDescriptor::CheckMemoryMapping(const std::vector<Arm11KernelCaps::sMemoryMapping>& maps)
{
	CheckMappingRangeWhiteList(maps, arm11_kernel_caps_.GetMemoryMapping(), valid_memory_mapping_);
}

void AccessDescriptor::CheckIORegisterMapping(const std::vector<Arm11KernelCaps::sMemoryMapping>& maps)
{
	CheckMappingRangeWhiteList(maps, arm11_kernel_caps_.GetIORegisterMapping(), valid_io_register_mapping_);
}

void AccessDescriptor::CheckIORights(const std::vector<Arm9AccessControl::IORight>& right_list)
{
	CheckWhiteList<Arm9AccessControl::IORight>(right_list, arm9_access_control_.GetIORights(), valid_io_rights_);
}

void AccessDescriptor::CheckDescVersion(u8 version)
{
	if (version == arm9_access_control_.GetDescVersion())
	{
		valid_desc_version_ = true;
	}
	else
	{
		valid_at_all_ = false;
		valid_desc_version_ = false;
	}
}

void AccessDescriptor::ClearDeserialisedVariables()
{
	valid_at_all_ = 0;
	valid_program_id_ = 0;
	valid_firmware_id_ = 0;
	valid_l2_cache_state_ = 0;
	valid_cpu_speed_ = 0;
	valid_system_mode_ext_ = 0;
	valid_ideal_processor_ = 0;
	valid_affinity_mask_ = 0;
	valid_system_mode_ = 0;
	valid_thread_priority_ = 0;
	valid_system_save_id_[0] = 0;
	valid_system_save_id_[1] = 0;
	valid_fs_rights_ = 0;
	valid_service_acl_ = 0;
	valid_interrupt_acl_ = 0;
	valid_system_call_acl_ = 0;
	valid_handle_table_size_ = 0;
	valid_kernel_flags_ = 0;
	valid_memory_type_ = 0;
	valid_memory_mapping_ = 0;
	valid_io_register_mapping_ = 0;
	valid_io_rights_ = 0;
	valid_desc_version_ = 0;
}

