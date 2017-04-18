#include "system_control_info.h"



SystemControlInfo::SystemControlInfo()
{
	ClearDeserialisedVariables();
}

SystemControlInfo::SystemControlInfo(const u8 * data)
{
	DeserialiseData(data);
}

SystemControlInfo::SystemControlInfo(const SystemControlInfo & other)
{
	DeserialiseData(other.GetSerialisedData());
}


SystemControlInfo::~SystemControlInfo()
{
}

void SystemControlInfo::operator=(const SystemControlInfo & other)
{
	DeserialiseData(other.GetSerialisedData());
}

const u8* SystemControlInfo::GetSerialisedData() const
{
	return serialised_data_.data();
}

size_t SystemControlInfo::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void SystemControlInfo::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sSystemControlInfo)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised sci");
	}

	sSystemControlInfo* sci = (sSystemControlInfo*)serialised_data_.data();

	sci->set_process_title(process_title_.c_str());
	sci->set_is_code_compressed(is_code_compressed_);
	sci->set_is_sdmc_title(is_sdmc_title_);
	sci->set_remaster_version(remaster_version_);
	sci->set_text(text_.address(), text_.page_num(), text_.size());
	sci->set_rodata(rodata_.address(), rodata_.page_num(), rodata_.size());
	sci->set_data(data_.address(), data_.page_num(), data_.size());
	sci->set_stack_size(stack_size_);
	sci->set_bss_size(bss_size_);
	for (size_t i = 0; i < dependency_list_.size(); i++)
	{
		sci->set_dependency(i, dependency_list_[i]);
	}
	sci->set_save_data_size(save_data_size_);
	sci->set_jump_id(jump_id_);
}

void SystemControlInfo::SetProcessTitle(const std::string & title)
{
	if (title.size() > kProcessTitleLength)
	{
		throw ProjectSnakeException(kModuleName, "Too long process title: \"" + title + "\" (maximum 8 characters)");
	}

	process_title_ = title; // copy
}

void SystemControlInfo::SetIsCodeCompressed(bool compressed)
{
	is_code_compressed_ = compressed;
}

void SystemControlInfo::SetIsSdmcTitle(bool sdmc_title)
{
	is_sdmc_title_ = sdmc_title;
}

void SystemControlInfo::SetRemasterVersion(u16 version)
{
	remaster_version_ = version;
}

void SystemControlInfo::SetTextSegmentInfo(u32 address, u32 page_num, u32 size)
{
	text_.set_address(address);
	text_.set_page_num(page_num);
	text_.set_size(size);
}

void SystemControlInfo::SetRodataSegmentInfo(u32 address, u32 page_num, u32 size)
{
	rodata_.set_address(address);
	rodata_.set_page_num(page_num);
	rodata_.set_size(size);
}

void SystemControlInfo::SetDataSegmentInfo(u32 address, u32 page_num, u32 size)
{
	data_.set_address(address);
	data_.set_page_num(page_num);
	data_.set_size(size);
}

void SystemControlInfo::SetStackSize(u32 size)
{
	stack_size_ = size;
}

void SystemControlInfo::SetBssSize(u32 size)
{
	bss_size_ = size;
}

void SystemControlInfo::SetDependencyList(const std::vector<u64>& list)
{
	if (list.size() > kMaxDependencyNum)
	{
		throw ProjectSnakeException(kModuleName, "Too many dependencies (max 48)");
	}

	dependency_list_.clear();
	for (size_t i = 0; i < list.size(); i++)
	{
		dependency_list_.push_back(list[i]);
	}
}

void SystemControlInfo::SetSaveDataSize(u32 size)
{
	save_data_size_ = size;
}

void SystemControlInfo::SetJumpId(u64 id)
{
	jump_id_ = id;
}

void SystemControlInfo::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();

	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sSystemControlInfo)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised sci");
	}
	memcpy(serialised_data_.data(), data, sizeof(sSystemControlInfo));

	const sSystemControlInfo* sci = (const sSystemControlInfo*)serialised_data_.data();

	process_title_ = std::string(sci->process_title(), kProcessTitleLength);
	is_code_compressed_ = sci->is_code_compressed();
	is_sdmc_title_ = sci->is_sdmc_title();
	remaster_version_ = sci->remaster_version();
	text_ = *sci->text();
	rodata_ = *sci->rodata();
	data_ = *sci->data();
	stack_size_ = sci->stack_size();
	bss_size_ = sci->bss_size();
	for (size_t i = 0; i < kMaxDependencyNum && sci->dependency(i) != 0; i++)
	{
		dependency_list_.push_back(sci->dependency(i));
	}
	save_data_size_ = sci->save_data_size();
	jump_id_ = sci->jump_id();
}

const std::string & SystemControlInfo::GetProcessTitle() const
{
	return process_title_;
}

bool SystemControlInfo::IsCodeCompressed() const
{
	return is_code_compressed_;
}

bool SystemControlInfo::IsSdmcTitle() const
{
	return is_sdmc_title_;
}

u16 SystemControlInfo::GetRemasterVersion() const
{
	return remaster_version_;
}

u32 SystemControlInfo::GetTextAddress() const
{
	return text_.address();
}

u32 SystemControlInfo::GetTextPageNum() const
{
	return text_.page_num();
}

u32 SystemControlInfo::GetTextSize() const
{
	return text_.size();
}

u32 SystemControlInfo::GetRodataAddress() const
{
	return rodata_.address();
}

u32 SystemControlInfo::GetRodataPageNum() const
{
	return rodata_.page_num();
}

u32 SystemControlInfo::GetRodataSize() const
{
	return rodata_.size();
}

u32 SystemControlInfo::GetDataAddress() const
{
	return data_.address();
}

u32 SystemControlInfo::GetDataPageNum() const
{
	return data_.page_num();
}

u32 SystemControlInfo::GetDataSize() const
{
	return data_.size();
}

u32 SystemControlInfo::GetStackSize() const
{
	return stack_size_;
}

u32 SystemControlInfo::GetBssSize() const
{
	return bss_size_;
}

const std::vector<u64> SystemControlInfo::GetDependencyList() const
{
	return dependency_list_;
}

u32 SystemControlInfo::GetSaveDataSize() const
{
	return save_data_size_;
}

u64 SystemControlInfo::GetJumpId() const
{
	return jump_id_;
}

void SystemControlInfo::ClearDeserialisedVariables()
{
	process_title_.clear();
	is_code_compressed_ = false;
	is_sdmc_title_ = false;
	remaster_version_ = 0;
	text_.clear();
	rodata_.clear();
	data_.clear();
	stack_size_ = 0;
	bss_size_ = 0;
	dependency_list_.clear();
	save_data_size_ = 0;
	jump_id_ = 0;
}
