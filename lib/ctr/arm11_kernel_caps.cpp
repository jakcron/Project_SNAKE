#include "arm11_kernel_caps.h"



Arm11KernelCaps::Arm11KernelCaps()
{
	ClearDeserialisedVariables();
}

Arm11KernelCaps::Arm11KernelCaps(const u8 * data)
{
	DeserialiseData(data);
}

Arm11KernelCaps::Arm11KernelCaps(const Arm11KernelCaps & other)
{
	DeserialiseData(other.GetSerialisedData());
}


Arm11KernelCaps::~Arm11KernelCaps()
{
}

void Arm11KernelCaps::operator=(const Arm11KernelCaps & other)
{
	DeserialiseData(other.GetSerialisedData());
}

const u8 * Arm11KernelCaps::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t Arm11KernelCaps::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void Arm11KernelCaps::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sArm11KernelCaps)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	sArm11KernelCaps* kern = (sArm11KernelCaps*)serialised_data_.data();

	// store caps
	std::vector<u32> interrupt_acl;
	std::vector<u32> system_call_acl;
	u32 release_kernel_version = 0;
	u32 handle_table_size = 0;
	u32 kernel_flags = 0;
	std::vector<u32> static_mappings;
	std::vector<u32> io_register_mappings;

	// serialise caps
	SerialiseSystemCalls(system_call_acl);
	SerialiseInterrupts(interrupt_acl);
	SerialiseReleaseKernelVersion(release_kernel_version);
	SerialiseHandleTableSize(handle_table_size);
	SerialiseKernelFlags(kernel_flags);
	SerialiseMemoryMappings(static_mappings);
	SerialiseIoRegisterMappings(io_register_mappings);

	// throw exception if too many kernel caps are specified
	if ((system_call_acl.size() \
		+ interrupt_acl.size() \
		+ io_register_mappings.size() \
		+ static_mappings.size() \
		+ (kernel_flags > 0) \
		+ (handle_table_size > 0) \
		+ (release_kernel_version > 0)) \
		> kKernelCapsNum)
	{
		throw ProjectSnakeException(kModuleName,"Too many kernel capabilities");
	}

	// commit capabilities to serialised data
	u32 pos, i;

	pos = 0;

	for (i = 0; i < system_call_acl.size() && pos < kKernelCapsNum; i++)
	{
		kern->set_kernel_capability(pos++, system_call_acl[i]);
	}

	for (i = 0; i < interrupt_acl.size() && pos < kKernelCapsNum; i++)
	{
		kern->set_kernel_capability(pos++, interrupt_acl[i]);
	}

	for (i = 0; i < io_register_mappings.size() && pos < kKernelCapsNum; i++)
	{
		kern->set_kernel_capability(pos++, io_register_mappings[i]);
	}

	for (i = 0; i < static_mappings.size() && pos < kKernelCapsNum; i++)
	{
		kern->set_kernel_capability(pos++, static_mappings[i]);
	}

	if (kernel_flags > 0 && pos < kKernelCapsNum)
	{
		kern->set_kernel_capability(pos++, kernel_flags);
	}

	if (handle_table_size > 0 && pos < kKernelCapsNum)
	{
		kern->set_kernel_capability(pos++, handle_table_size);
	}

	if (release_kernel_version > 0 && pos < kKernelCapsNum)
	{
		kern->set_kernel_capability(pos++, release_kernel_version);
	}

	// write dummy data to remaining descriptors
	for (; pos < kKernelCapsNum; pos++)
	{
		kern->set_kernel_capability(pos++, make_capability(PREFIX_UNUSED, 0));
	}
}

void Arm11KernelCaps::SetInterruptACL(const std::vector<u8>& list)
{
	if (list.size() > kMaxStoredInteruptNum)
	{
		throw ProjectSnakeException(kModuleName, "Too many interupts (max 32)");
	}

	for (size_t i = 0; i < list.size(); i++)
	{
		interrupt_acl_.push_back(list[i]);
	}
}

void Arm11KernelCaps::SetSystemCallACL(const std::vector<u8>& list)
{
	for (size_t i = 0; i < list.size(); i++)
	{
		interrupt_acl_.push_back(list[i]);
	}
}

void Arm11KernelCaps::SetReleaseKernelVersion(u16 version)
{
	release_kernel_version_ = version;
}

void Arm11KernelCaps::SetHandleTableSize(u16 size)
{
	handle_table_size_ = size;
}

void Arm11KernelCaps::SetMemoryType(MemoryType type)
{
	memory_type_ = type;
}

void Arm11KernelCaps::SetKernelFlags(u32 flags)
{
	kernel_flag_ = 0;
	kernel_flag_list_.clear();
	// also save appropriate bits, and as list
	for (u8 i = 0; i <= MAX_KERNEL_FLAG; i++)
	{
		// skip these bits
		if (i == MEMORY_TYPE_RESERVED_0 || i == MEMORY_TYPE_RESERVED_1 || i == MEMORY_TYPE_RESERVED_2 || i == MEMORY_TYPE_RESERVED_3) continue;

		if (flags & BIT(i))
		{
			kernel_flag_ |= BIT(i);
			kernel_flag_list_.push_back((KernelFlag)i);
		}
	}
}

void Arm11KernelCaps::SetKernelFlags(const std::vector<KernelFlag>& flags)
{
	kernel_flag_ = 0;
	kernel_flag_list_.clear();
	// save appropriate bits
	for (size_t i = 0; i < flags.size(); i++)
	{
		// skip these bits
		if (flags[i] == MEMORY_TYPE_RESERVED_0 || flags[i] == MEMORY_TYPE_RESERVED_1 || flags[i] == MEMORY_TYPE_RESERVED_2 || flags[i] == MEMORY_TYPE_RESERVED_3)
		{
			throw ProjectSnakeException(kModuleName, "Illegal kernel flag");
		}
		if (flags[i] > MAX_KERNEL_FLAG)
		{
			throw ProjectSnakeException(kModuleName, "Illegal kernel flag");
		}

		kernel_flag_ |= BIT(flags[i]);
	}
	// also save as list
	for (u8 i = 0; i < sizeof(u32) * 8; i++)
	{
		if (kernel_flag_ & BIT(i))
		{
			kernel_flag_list_.push_back((KernelFlag)i);
		}
	}
}

void Arm11KernelCaps::SetStaticMapping(const std::vector<struct sMemoryMapping>& mapping_list)
{
	memory_mapping_.clear();
	for (size_t i = 0; i < mapping_list.size(); i++)
	{
		memory_mapping_.push_back(mapping_list[i]);
	}
}

void Arm11KernelCaps::SetIOMapping(const std::vector<struct sMemoryMapping>& mapping_list)
{
	io_register_mapping_.clear();
	for (size_t i = 0; i < mapping_list.size(); i++)
	{
		io_register_mapping_.push_back(mapping_list[i]);
	}
}

void Arm11KernelCaps::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();

	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sArm11KernelCaps)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	memcpy(serialised_data_.data(), data, sizeof(sArm11KernelCaps));

	const sArm11KernelCaps* kern = (const sArm11KernelCaps*)serialised_data_.data_const();

	std::vector<u32> interrupt_acl;
	std::vector<u32> system_call_acl;


	// collect capabilities
	for (int i = 0; i < kKernelCapsNum && kern->kernel_capability(i) != make_capability(PREFIX_UNUSED, 0); i++)
	{
		switch (get_capability_prefix(kern->kernel_capability(i)))
		{
		case(PREFIX_INTERRUPT) :
			// save to process all at once
			interrupt_acl.push_back(get_capability_data(PREFIX_INTERRUPT, kern->kernel_capability(i)));
			break;
		case(PREFIX_SYSTEM_CALL):
			// save to process all at once
			system_call_acl.push_back(get_capability_data(PREFIX_SYSTEM_CALL, kern->kernel_capability(i)));
			break;
		case(PREFIX_RELEASE_KERNEL_VERSION):
			release_kernel_version_ = get_capability_data(PREFIX_RELEASE_KERNEL_VERSION, kern->kernel_capability(i));
			break;
		case(PREFIX_HANDLE_TABLE_SIZE):
			handle_table_size_ = get_capability_data(PREFIX_HANDLE_TABLE_SIZE, kern->kernel_capability(i));
			break;
		case(PREFIX_KERNEL_FLAG):
			DeserialiseKernelFlag(get_capability_data(PREFIX_KERNEL_FLAG, kern->kernel_capability(i)));
			break;
		case(PREFIX_MAPPING_PAGE_RANGE):
			// check there are two caps
			if (i >= kKernelCapsNum - 1 || get_capability_prefix(kern->kernel_capability(i + 1)) != PREFIX_MAPPING_PAGE_RANGE)
			{
				throw ProjectSnakeException(kModuleName, "Unclosed mapped memory range");
			}
			DeserialisePageRangeMapping(get_capability_data(PREFIX_MAPPING_PAGE_RANGE, kern->kernel_capability(i)), get_capability_data(PREFIX_MAPPING_PAGE_RANGE, kern->kernel_capability(i+1)));
			i++; // skip next one since it has already been deserialised
			break;
		case(PREFIX_MAPPING_PAGE):
			DeserialisePageMapping(get_capability_data(PREFIX_MAPPING_PAGE, kern->kernel_capability(i)));
			break;
		default:
			throw ProjectSnakeException(kModuleName, "Illegal arm11 kernel capability");
		}
	}

	DeserialiseInterrupt(interrupt_acl);
	DeserialiseSystemCall(system_call_acl);
}

const std::vector<u8>& Arm11KernelCaps::GetInterruptACL() const
{
	return interrupt_acl_;
}

const std::vector<u8>& Arm11KernelCaps::GetSystemCallACL() const
{
	return systemcall_acl_;
}

u16 Arm11KernelCaps::GetReleaseKernelVersion() const
{
	return release_kernel_version_;
}

u16 Arm11KernelCaps::GetHandleTableSize() const
{
	return handle_table_size_;
}

Arm11KernelCaps::MemoryType Arm11KernelCaps::GetMemoryType() const
{
	return memory_type_;
}

u32 Arm11KernelCaps::GetKernelFlags() const
{
	return kernel_flag_;
}

const std::vector<Arm11KernelCaps::KernelFlag>& Arm11KernelCaps::GetKernelFlagList() const
{
	return kernel_flag_list_;
}

const std::vector<Arm11KernelCaps::sMemoryMapping>& Arm11KernelCaps::GetMemoryMapping() const
{
	return memory_mapping_;
}

const std::vector<Arm11KernelCaps::sMemoryMapping>& Arm11KernelCaps::GetIORegisterMapping() const
{
	return io_register_mapping_;
}

void Arm11KernelCaps::ClearDeserialisedVariables()
{
	interrupt_acl_.clear();
	systemcall_acl_.clear();
	release_kernel_version_ = 0;
	handle_table_size_ = 0;
	memory_type_ = MemoryType::APPLICATION;
	kernel_flag_ = 0;
	kernel_flag_list_.clear();
	memory_mapping_.clear();
	io_register_mapping_.clear();
}

void Arm11KernelCaps::SerialiseInterrupts(std::vector<u32>& interupt_caps)
{
	const size_t MAX_DESC = kMaxInteruptNum / 4;
	u32 desc[MAX_DESC] = { 0 }; // 4 interupts can exist in a descriptor
	u32 i, j;
	for (i = j = 0; j < interrupt_acl_.size() && i < kMaxStoredInteruptNum; i++, j++)
	{
		// skip over invalid interupt values
		while (interrupt_acl_[j] > kMaxInteruptValue && j < interrupt_acl_.size())
		{
			j++;
		}

		// break if we exceed the list size
		if (j >= interrupt_acl_.size())
		{
			break;
		}

		// if this is a new desc, set all bits
		if (i % 4)
		{
			desc[i / 4] = 0xffffffff;
		}

		// shift the desc 7 bits
		desc[i / 4] = (desc[i / 4] << 7) | interrupt_acl_[j];
	}
	for (i = 0; i < MAX_DESC; i++)
	{
		if (desc[i] > 0)
		{
			interupt_caps.push_back(make_capability(PREFIX_INTERRUPT, desc[i]));
		}
	}
}

void Arm11KernelCaps::SerialiseSystemCalls(std::vector<u32>& system_call_caps)
{
	u32 desc[8] = { 0 };
	for (u32 i = 0; i < systemcall_acl_.size(); i++)
	{
		if (systemcall_acl_[i] > kMaxSvcValue)
		{
			continue;
		}

		desc[(systemcall_acl_[i] / 24)] |= 1 << ((systemcall_acl_[i] % 24) & 31);
	}
	for (u32 i = 0; i < 8; i++)
	{
		if (desc[i] > 0)
		{
			system_call_caps.push_back(make_capability(PREFIX_SYSTEM_CALL | (i << 24), desc[i]));
		}
	}
}

void Arm11KernelCaps::SerialiseReleaseKernelVersion(u32 & release_kernel_version)
{
	if (release_kernel_version_ != 0)
	{
		release_kernel_version = make_capability(PREFIX_RELEASE_KERNEL_VERSION, release_kernel_version_);
	}
}

void Arm11KernelCaps::SerialiseHandleTableSize(u32 & handle_table_size)
{
	if (handle_table_size_ != 0)
	{
		handle_table_size = make_capability(PREFIX_HANDLE_TABLE_SIZE, handle_table_size_);
	}
}

void Arm11KernelCaps::SerialiseKernelFlags(u32 & kernel_flags)
{
	u32 data = ((memory_type_ & kMemoryTypeMask) << kMemoryTypeShift) | kernel_flag_;

	if (data != 0)
	{
		kernel_flags = make_capability(PREFIX_KERNEL_FLAG, data);
	}
}

void Arm11KernelCaps::SerialiseMemoryMappings(std::vector<u32>& static_mapping)
{
	for (size_t i = 0; i < memory_mapping_.size(); i++)
	{
		if (memory_mapping_[i].start == 0)
		{
			continue;
		}

		// if the end offset is valid
		if (align_to_page(memory_mapping_[i].end) > memory_mapping_[i].start)
		{
			static_mapping.push_back(make_capability(PREFIX_MAPPING_PAGE_RANGE, make_mapping_data(memory_mapping_[i].start, memory_mapping_[i].read_only)));
			static_mapping.push_back(make_capability(PREFIX_MAPPING_PAGE_RANGE, make_mapping_data(align_to_page(memory_mapping_[i].end), true)));
		}
		else
		{
			static_mapping.push_back(make_capability(PREFIX_MAPPING_PAGE_RANGE, make_mapping_data(memory_mapping_[i].start, memory_mapping_[i].read_only)));
			static_mapping.push_back(make_capability(PREFIX_MAPPING_PAGE_RANGE, make_mapping_data(memory_mapping_[i].start + 0x1000, true)));
		}

	}
}

void Arm11KernelCaps::SerialiseIoRegisterMappings(std::vector<u32>& io_mapping)
{
	for (size_t i = 0; i < io_register_mapping_.size(); i++)
	{
		if (io_register_mapping_[i].start == 0)
		{
			continue;
		}

		// if the end offset is valid
		if (align_to_page(io_register_mapping_[i].end) > io_register_mapping_[i].start)
		{
			io_mapping.push_back(make_capability(PREFIX_MAPPING_PAGE_RANGE, make_mapping_data(io_register_mapping_[i].start, false)));
			io_mapping.push_back(make_capability(PREFIX_MAPPING_PAGE_RANGE, make_mapping_data(align_to_page(io_register_mapping_[i].end), false)));
		}
		else
		{
			io_mapping.push_back(make_capability(PREFIX_MAPPING_PAGE, make_mapping_data(io_register_mapping_[i].start, false)));
		}
	}
}

void Arm11KernelCaps::DeserialiseInterrupt(const std::vector<u32>& interrupt_caps)
{
	u8 interrupt_enabled[kMaxInteruptNum] = { 0 };

	for (size_t i = 0; i < interrupt_caps.size(); i++)
	{
		for (u8 j = 0; j < 4; j++)
		{
			interrupt_enabled[(interrupt_caps[i] >> j * 7) & kMaxInteruptValue] = 1;
		}
	}

	interrupt_acl_.clear();
	for (u8 i = 0; i < kMaxInteruptNum; i++)
	{
		if (interrupt_enabled[i] == 1)
		{
			interrupt_acl_.push_back(i);
		}
	}
}

void Arm11KernelCaps::DeserialiseSystemCall(const std::vector<u32>& system_call_caps)
{
	u8 syscall_enabled[kMaxSvcNum] = { 0 };

	for (size_t i = 0; i < system_call_caps.size(); i++)
	{
		u8 syscall_group = (system_call_caps[i] >> kSyscallShift) * kSyscallShift;
		for (u8 j = 0; j < kSyscallShift; j++)
		{
			if ((system_call_caps[i] & BIT(j)) == BIT(j))
			{
				syscall_enabled[syscall_group + j] = 1;
			}
		}
	}

	systemcall_acl_.clear();
	for (u8 i = 0; i < kMaxSvcNum; i++)
	{
		if (syscall_enabled[i] == 1)
		{
			systemcall_acl_.push_back(i);
		}
	}
}

void Arm11KernelCaps::DeserialiseKernelFlag(u32 data)
{
	SetKernelFlags(data);

	memory_type_ = (MemoryType)((data >> kMemoryTypeShift) & kMemoryTypeMask);
}

void Arm11KernelCaps::DeserialisePageRangeMapping(u32 start, u32 end)
{
	sMemoryMapping map;
	map.start = get_mapping_address(start);
	map.end = get_mapping_address(end)-1;
	map.read_only = is_mapping_readonly(start);

	// static mappings have read only end addresses, io mappings do not
	if (is_mapping_readonly(end))
	{
		memory_mapping_.push_back(map);
	}
	else
	{
		io_register_mapping_.push_back(map);
	}
}

void Arm11KernelCaps::DeserialisePageMapping(u32 data)
{
	sMemoryMapping map;
	map.start = get_mapping_address(data);
	map.end = 0;
	map.read_only = false;

	// only io mappings have single page maps
	io_register_mapping_.push_back(map);
}
