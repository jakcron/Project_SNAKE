#include "arm11_local_caps.h"



Arm11LocalCaps::Arm11LocalCaps()
{
	ClearDeserialisedVariables();
}

Arm11LocalCaps::Arm11LocalCaps(const u8 * data)
{
	DeserialiseData(data);
}

Arm11LocalCaps::Arm11LocalCaps(const Arm11LocalCaps & other)
{
	DeserialiseData(other.GetSerialisedData());
}


Arm11LocalCaps::~Arm11LocalCaps()
{
}

void Arm11LocalCaps::operator=(const Arm11LocalCaps & other)
{
	DeserialiseData(other.GetSerialisedData());
}

const u8 * Arm11LocalCaps::GetSerialisedData() const
{
	return serialised_data_.data();
}

size_t Arm11LocalCaps::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void Arm11LocalCaps::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sArm11LocalCapabilities)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	sArm11LocalCapabilities* local = (sArm11LocalCapabilities*)serialised_data_.data();

	// detect illegal combinination of variables
	if ((extdata_id_ != 0 || other_user_save_id_[0] != 0 || other_user_save_id_[1] != 0 || other_user_save_id_[2] != 0) && accessible_save_ids_.size() > 0)
	{
		throw ProjectSnakeException(kModuleName, "Extdata id or other-user save ids cannot be set inconjunction with accessible save ids");
	}


	local->set_program_id(program_id_);
	local->set_firm_title_id(firm_title_id_);
	local->set_enable_l2_cache(is_l2_cache_enabled_);
	local->set_cpu_speed(cpu_speed_);
	local->set_system_mode_ext(system_mode_ext_);
	local->set_ideal_processor(ideal_processor_);
	local->set_affinity_mask(affinity_mask_);
	local->set_system_mode(system_mode_);
	local->set_thread_priority(thread_priority_);
	local->set_resource_limit_descriptor(0, max_cpu_time_);
	local->set_use_other_variation_save_data(use_other_variation_save_data_);
	local->set_fs_attribute_bit(NOT_USE_ROMFS, !mount_romfs_);
	local->set_fs_rights(fs_rights_);
	local->set_resource_limit_category(resource_limit_category_);

	for (size_t i = 0; i < kSystemSaveIdNum; i++)
	{
		local->set_system_save_id(i, system_save_id_[i]);
	}

	if (accessible_save_ids_.size() > 0)
	{
		size_t num = accessible_save_ids_.size() < kMaxAccessibleSaveIdNum ? accessible_save_ids_.size() : kMaxAccessibleSaveIdNum;
		for (size_t i = 0; i < num; i++)
		{
			// manipulate index to simulate the lazy method used in sdk makerom
			int index = 0;
			if (i < 3)
			{
				index = i + ((kMaxAccessibleSaveIdNum - num) - 3);
			}
			else
			{
				index = i + (kMaxAccessibleSaveIdNum - num);
			}
			

			local->set_accessible_save_id(index, accessible_save_ids_[i]);
		}

		// set bit to show this is being used
		local->set_fs_attribute_bit(USE_EXTENDED_SAVEDATA_ACCESS_CONTROL, true);
	}
	else
	{
		local->set_extdata_id(extdata_id_);

		for (size_t i = 0; i < kOtherUserSaveIdNum; i++)
		{
			local->set_other_user_save_id(i, other_user_save_id_[i]);
		}
	}

	for (size_t i = 0; i < service_acl_.size(); i++)
	{
		local->set_service(i, service_acl_[i].c_str());
	}
}

void Arm11LocalCaps::SetProgramId(u64 program_id)
{
	program_id_ = program_id;
}

void Arm11LocalCaps::SetFirmTitleId(u64 title_id)
{
	firm_title_id_ = title_id;
}

void Arm11LocalCaps::EnableL2Cache(bool enable)
{
	is_l2_cache_enabled_ = enable;
}

void Arm11LocalCaps::SetCpuSpeed(CpuSpeed speed)
{
	cpu_speed_ = speed;
}

void Arm11LocalCaps::SetSystemModeExt(SystemModeExt system_mode)
{
	system_mode_ext_ = system_mode;
}

void Arm11LocalCaps::SetIdealProcessor(u8 ideal_processor)
{
	if (ideal_processor > kMaxIdealProcessor)
	{
		throw ProjectSnakeException(kModuleName, "Illegal 'Ideal Processor' value (range: 0-3)");
	}

	ideal_processor_ = ideal_processor;
}

void Arm11LocalCaps::SetAffinityMask(u8 affinity_mask)
{
	if (affinity_mask > kMaxAffinityMask)
	{
		throw ProjectSnakeException(kModuleName, "Illegal 'Affinity Mask' value (range: 0-3)");
	}

	affinity_mask_ = affinity_mask;
}

void Arm11LocalCaps::SetSystemMode(SystemMode system_mode)
{
	system_mode_ = system_mode;
}

void Arm11LocalCaps::SetThreadPriority(int8_t priority)
{
	if (priority < 0)
	{
		throw ProjectSnakeException(kModuleName, "Illegal 'Thread Priority' value (range: 0-127)");
	}

	thread_priority_ = priority;
}

void Arm11LocalCaps::SetMaxCpuTime(u16 max_time)
{
	max_cpu_time_ = max_time;
}

void Arm11LocalCaps::SetExtdataId(u64 extdata_id)
{
	extdata_id_ = extdata_id;
}

void Arm11LocalCaps::SetSystemSaveIds(u32 save_id1, u32 save_id2)
{
	system_save_id_[0] = save_id1;
	system_save_id_[1] = save_id2;
}

void Arm11LocalCaps::SetSystemSaveIds(const std::vector<u32>& id_list)
{
	if (id_list.size() > kSystemSaveIdNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal number of 'SystemSaveIds' (max: 2)");
	}

	for (size_t i = 0; i < id_list.size(); i++)
	{
		system_save_id_[i] = id_list[i];
	}
}

void Arm11LocalCaps::SetOtherUserSaveIds(u32 save_id1, u32 save_id2, u32 save_id3)
{
	other_user_save_id_[0] = save_id1;
	other_user_save_id_[1] = save_id2;
	other_user_save_id_[2] = save_id3;
}

void Arm11LocalCaps::SetOtherUserSaveIds(const std::vector<u32>& id_list)
{
	if (id_list.size() > kOtherUserSaveIdNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal number of 'OtherUserSaveIds' (max: 3)");
	}

	for (size_t i = 0; i < id_list.size(); i++)
	{
		other_user_save_id_[i] = id_list[i];
	}
}

void Arm11LocalCaps::SetAccessibleSaveIds(const std::vector<u32>& id_list)
{
	if (id_list.size() > kMaxAccessibleSaveIdNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal number of 'Accessible Save IDs' (max: 6)");
	}

	accessible_save_ids_.clear();
	for (size_t i = 0; i < id_list.size(); i++)
	{
		accessible_save_ids_.push_back(id_list[i]);
	}
}

void Arm11LocalCaps::AllowAccessOtherVariationSaveData(bool allow)
{
	use_other_variation_save_data_ = allow;
}

void Arm11LocalCaps::SetFsRights(u64 fs_rights)
{
	fs_rights_ = fs_rights & kFsRightsMask;

	fs_right_list_.clear();
	for (u8 i = 0; i < kMaxFsRight; i++)
	{
		fs_right_list_.push_back((FSRight)i);
	}
}

void Arm11LocalCaps::SetFsRights(const std::vector<FSRight>& fs_right_list)
{
	u64 rights = 0;
	for (size_t i = 0; i < fs_right_list.size(); i++)
	{
		rights |= BIT(fs_right_list[i]);
	}

	SetFsRights(rights);
}

void Arm11LocalCaps::AllowUseRomfs(bool allow)
{
	mount_romfs_ = allow;
}

void Arm11LocalCaps::SetServiceACL(const std::vector<std::string>& service_list)
{
	if (service_list.size() > kMaxServiceNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal number of 'Services' (max: 34)");
	}

	service_acl_.clear();
	for (size_t i = 0; i < service_list.size(); i++)
	{
		service_acl_.push_back(service_list[i]);
	}
}

void Arm11LocalCaps::SetResourceLimitCategory(ResourceLimitCategory category)
{
	resource_limit_category_ = category;
}

void Arm11LocalCaps::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();

	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sArm11LocalCapabilities)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	memcpy(serialised_data_.data(), data, sizeof(sArm11LocalCapabilities));

	const sArm11LocalCapabilities* local = (const sArm11LocalCapabilities*)serialised_data_.data();

	program_id_ = local->program_id();
	firm_title_id_ = local->firm_title_id();
	is_l2_cache_enabled_ = local->is_l2_cache_enabled();
	cpu_speed_ = local->cpu_speed();
	system_mode_ext_ = local->system_mode_ext();
	ideal_processor_ = local->ideal_processor();
	affinity_mask_ = local->affinity_mask();
	system_mode_ = local->system_mode();
	thread_priority_ = local->thread_priority();
	max_cpu_time_ = local->resource_limit_descriptor(0);
	use_other_variation_save_data_ = local->use_other_variation_save_data();
	mount_romfs_ = !local->fs_attribute_has_bit(NOT_USE_ROMFS);
	resource_limit_category_ = local->resource_limit_category();

	// depending on a flag, different regions are set
	if (local->fs_attribute_has_bit(USE_EXTENDED_SAVEDATA_ACCESS_CONTROL))
	{
		extdata_id_ = 0;
		for (u32 i = 0; i < kMaxAccessibleSaveIdNum; i++)
		{
			if (local->accessible_save_id(i) != 0)
			{
				accessible_save_ids_.push_back(local->accessible_save_id(i));
			}
		}
	}
	else
	{
		extdata_id_ = local->extdata_id();
		for (u32 i = 0; i < kOtherUserSaveIdNum; i++)
		{
			other_user_save_id_[i] = local->other_user_save_id(i);
		}
	}

	// save system save ids
	for (u32 i = 0; i < kSystemSaveIdNum; i++)
	{
		system_save_id_[i] = local->system_save_id(i);
	}

	// save fs rights
	fs_rights_ = local->fs_rights();
	for (u8 i = 0; i < kMaxFsRight; i++)
	{
		if (local->fs_rights_has_bit(i))
		{
			fs_right_list_.push_back((FSRight)i);
		}
	}

	// save service acl
	for (u32 i = 0; i < kMaxServiceNum && local->service(i)[0] != '\0'; i++)
	{
		service_acl_.push_back(std::string(local->service(i), kServiceNameMaxLen));
	}
}

u64 Arm11LocalCaps::GetProgramId() const
{
	return program_id_;
}

u64 Arm11LocalCaps::GetFirmTitleId() const
{
	return firm_title_id_;
}

bool Arm11LocalCaps::IsL2CacheEnabled() const
{
	return is_l2_cache_enabled_;
}

Arm11LocalCaps::CpuSpeed Arm11LocalCaps::GetCpuSpeed() const
{
	return cpu_speed_;
}

Arm11LocalCaps::SystemModeExt Arm11LocalCaps::GetSystemModeExt() const
{
	return system_mode_ext_;
}

u8 Arm11LocalCaps::GetIdealProcessor() const
{
	return ideal_processor_;
}

u8 Arm11LocalCaps::GetAffinityMask() const
{
	return affinity_mask_;
}

Arm11LocalCaps::SystemMode Arm11LocalCaps::GetSystemMode() const
{
	return system_mode_;
}

int8_t Arm11LocalCaps::GetThreadPriority() const
{
	return thread_priority_;
}

u16 Arm11LocalCaps::GetMaxCpuTime() const
{
	return max_cpu_time_;
}

u64 Arm11LocalCaps::GetExtdataId() const
{
	return extdata_id_;
}

u32 Arm11LocalCaps::GetSystemSaveId1() const
{
	return system_save_id_[0];
}

u32 Arm11LocalCaps::GetSystemSaveId2() const
{
	return system_save_id_[1];
}

u32 Arm11LocalCaps::GetOtherUserSaveId1() const
{
	return other_user_save_id_[0];
}

u32 Arm11LocalCaps::GetOtherUserSaveId2() const
{
	return other_user_save_id_[1];
}

u32 Arm11LocalCaps::GetOtherUserSaveId3() const
{
	return other_user_save_id_[2];
}

const std::vector<u32>& Arm11LocalCaps::GetAccessibleSaveIds() const
{
	return accessible_save_ids_;
}

bool Arm11LocalCaps::CanAccessOtherVariationSaveData() const
{
	return use_other_variation_save_data_;
}

u64 Arm11LocalCaps::GetFsRights() const
{
	return fs_rights_;
}

const std::vector<Arm11LocalCaps::FSRight>& Arm11LocalCaps::GetFsRightList() const
{
	return fs_right_list_;
}

bool Arm11LocalCaps::HasFsRight(FSRight right)
{
	return (fs_rights_ & BIT(right)) == BIT(right);
}

bool Arm11LocalCaps::CanMountRomfs() const
{
	return mount_romfs_;
}

const std::vector<std::string>& Arm11LocalCaps::GetServiceACL() const
{
	return service_acl_;
}

Arm11LocalCaps::ResourceLimitCategory Arm11LocalCaps::GetResourceLimitCategory() const
{
	return resource_limit_category_;
}

void Arm11LocalCaps::ClearDeserialisedVariables()
{
	program_id_ = 0;
	firm_title_id_ = 0;
	is_l2_cache_enabled_ = false;
	cpu_speed_ = CpuSpeed::CLOCK_268MHz;
	system_mode_ext_ = SystemModeExt::SYSMODE_SNAKE_LEGACY;
	ideal_processor_ = 0;
	affinity_mask_ = 0;
	system_mode_ = SystemMode::SYSMODE_PROD;
	thread_priority_ = 0;
	max_cpu_time_ = 0;
	extdata_id_ = 0;
	system_save_id_[0] = 0;
	system_save_id_[1] = 0;
	other_user_save_id_[0] = 0;
	other_user_save_id_[1] = 0;
	other_user_save_id_[2] = 0;
	use_other_variation_save_data_ = false;
	accessible_save_ids_.clear();
	fs_rights_ = 0;
	fs_right_list_.clear();
	mount_romfs_ = false;
	service_acl_.clear();
	resource_limit_category_ = ResourceLimitCategory::RESLIMIT_APPLICATION;
}
