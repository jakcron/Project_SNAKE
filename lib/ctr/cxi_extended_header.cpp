#include <cstdlib>
#include <cstring>
#include "cxi_extended_header.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

CxiExtendedHeader::CxiExtendedHeader()
{
	memset((u8*)&header_, 0, sizeof(struct sExtendedHeader));
	memset((u8*)&access_descriptor_, 0, sizeof(struct sAccessDescriptor));
}

CxiExtendedHeader::~CxiExtendedHeader()
{

}

int CxiExtendedHeader::CreateExheader(const Crypto::sRsa2048Key& ncch_rsa, const Crypto::sRsa2048Key& accessdesc_rsa)
{
	u8 hash[0x20];

	safe_call(CommitArm11KernelCapabilities());

	// Copy NCCH Modulus
	memcpy(access_descriptor_.ncch_rsa_modulus, ncch_rsa.modulus, Crypto::kRsa2048Size);

	// Copy exheader data
	memcpy((u8*)&access_descriptor_.arm11_local, (u8*)&header_.arm11_local, sizeof(struct sArm11LocalCapabilities));
	memcpy((u8*)&access_descriptor_.arm11_kernel, (u8*)&header_.arm11_kernel, sizeof(struct sArm11KernelCapabilities));
	memcpy((u8*)&access_descriptor_.arm9, (u8*)&header_.arm9, sizeof(struct sArm9AccessControl));

	// Modify data
	access_descriptor_.arm11_local.ideal_processor = 1 << access_descriptor_.arm11_local.ideal_processor;
	access_descriptor_.arm11_local.thread_priority = 0;//access_descriptor_.arm11_local.thread_priority/2; // thread priority cannot be lower than in accessdesc

	// Sign data
	Crypto::Sha256((u8*)&access_descriptor_.ncch_rsa_modulus, sizeof(struct sAccessDescriptor) - Crypto::kRsa2048Size, hash);
	safe_call(Crypto::RsaSign(accessdesc_rsa, Crypto::HASH_SHA256, hash, access_descriptor_.signature));

	return 0;
}

int CxiExtendedHeader::SetData(const u8* exheader, const u8* accessdesc)
{
	memcpy((u8*)&header_, exheader, sizeof(struct sExtendedHeader));
	memcpy((u8*)&access_descriptor_, accessdesc, sizeof(struct sAccessDescriptor));
	return 0;
}

// Set Process Info
void CxiExtendedHeader::SetProcessName(const char* name)
{
	memset(header_.process_info.name, 0, 8);
	strncpy(header_.process_info.name, name, 8);
}

void CxiExtendedHeader::SetIsCodeCompressed(bool is_code_compressed)
{
	header_.process_info.is_code_compressed = is_code_compressed;
}

void CxiExtendedHeader::SetIsSdmcTitle(bool is_sdmc_title)
{
	header_.process_info.is_sdmc_title = is_sdmc_title;
}

void CxiExtendedHeader::SetRemasterVersion(u16 version)
{
	header_.process_info.remaster_version = le_hword(version);
}

void CxiExtendedHeader::SetTextSegment(u32 address, u32 page_num, u32 size)
{
	header_.process_info.code_info.text.address = le_word(address);
	header_.process_info.code_info.text.page_num = le_word(page_num);
	header_.process_info.code_info.text.size = le_word(size);
}

void CxiExtendedHeader::SetRoDataSegment(u32 address, u32 page_num, u32 size)
{
	header_.process_info.code_info.rodata.address = le_word(address);
	header_.process_info.code_info.rodata.page_num = le_word(page_num);
	header_.process_info.code_info.rodata.size = le_word(size);
}

void CxiExtendedHeader::SetDataSegment(u32 address, u32 page_num, u32 size)
{
	header_.process_info.code_info.data.address = le_word(address);
	header_.process_info.code_info.data.page_num = le_word(page_num);
	header_.process_info.code_info.data.size = le_word(size);
}

void CxiExtendedHeader::SetStackSize(u32 stack_size)
{
	header_.process_info.code_info.stack_size = le_word(stack_size);
}

void CxiExtendedHeader::SetBssSize(u32 bss_size)
{
	header_.process_info.code_info.bss_size = le_word(bss_size);
}

int CxiExtendedHeader::SetDependencyList(const std::vector<u64>& dependency_list)
{
	if (dependency_list.size() > kMaxDependencyNum)
	{
		die("[ERROR] Too many Dependencies. (Maximum 48)");
	}

	for (u32 i = 0; i < dependency_list.size() && i < kMaxDependencyNum; i++)
	{
		header_.process_info.dependency_list[i] = le_dword(dependency_list[i]);
	}
    
    return 0;
}

void CxiExtendedHeader::SetSaveDataSize(u32 size)
{
	header_.process_info.save_data_size = le_word(size);
}

void CxiExtendedHeader::SetJumpId(u64 id)
{
	header_.process_info.jump_id = le_dword(id);
}


// Set Arm11 Local Capabilities
void CxiExtendedHeader::SetProgramId(u64 id)
{
	header_.arm11_local.program_id = le_dword(id);
}

void CxiExtendedHeader::SetFirmwareTitleId(u64 id)
{
	header_.arm11_local.firm_title_id_low = le_word(id&0x0fffffff);
}

void CxiExtendedHeader::SetEnableL2Cache(bool enable)
{
	header_.arm11_local.enable_l2_cache = enable;
}

void CxiExtendedHeader::SetCpuSpeed(CpuSpeed speed)
{
	header_.arm11_local.cpu_speed = (speed == CLOCK_804MHz);
}

void CxiExtendedHeader::SetSystemModeExt(SystemModeExt mode)
{
	header_.arm11_local.system_mode_ext = mode; 
}

int CxiExtendedHeader::SetIdealProcessor(u8 processor)
{
	if (processor > 1)
	{
		die("[ERROR] Invalid IdealProcessor. (Only 0 or 1 allowed)");
	}

	header_.arm11_local.ideal_processor = processor; 

	return 0;
}

int CxiExtendedHeader::SetProcessAffinityMask(u8 affinity_mask)
{
	if (affinity_mask > 3)
	{
		die("[ERROR] AffinityMask is too large. (Maximum 3)");
	}

	header_.arm11_local.affinity_mask = affinity_mask;

	return 0;
}

void CxiExtendedHeader::SetSystemMode(SystemMode mode)
{
	header_.arm11_local.system_mode = mode; 
}

int CxiExtendedHeader::SetProcessPriority(int8_t priority)
{
	if (priority < 0)
	{
		die("[ERROR] Invalid Priority. (Allowed range: 0-127).");
	}

	header_.arm11_local.thread_priority = priority; 

	return 0;
}

void CxiExtendedHeader::SetExtdataId(u64 id)
{
	header_.arm11_local.extdata_id = le_dword(id);
	header_.arm11_local.fs_rights &= ~le_dword(USE_EXTENDED_SAVEDATA_ACCESS_CONTROL);
}

int CxiExtendedHeader::SetSystemSaveIds(const std::vector<u32>& ids)
{
	if (ids.size() > kMaxSystemSaveIdNum)
	{
		die("[ERROR] Too many SystemSaveIds. (Maximum 2)");
	}

	for (u32 i = 0; i < ids.size() && i < kMaxSystemSaveIdNum; i++)
	{
		header_.arm11_local.system_save_ids[i] = le_word(ids[i]);
	}

	return 0;
}

int CxiExtendedHeader::SetOtherUserSaveIds(const std::vector<u32>& ids, bool use_other_variation_save_data)
{
	u64 saveIds = 0;

	if (ids.size() > 3)
	{
		die("[ERROR] Too many OtherUserSaveIds. (Maximum 3)");
	}

	for (u32 i = 0; i < ids.size() && i < 3; i++)
	{
		saveIds = (saveIds << 20) | (ids[i] & 0xffffff);
	}

	// set bit60 if use_other_variation_save_data
	if (use_other_variation_save_data)
	{
		saveIds |= BIT(60);
	}
		

	header_.arm11_local.fs_rights &= ~le_dword(USE_EXTENDED_SAVEDATA_ACCESS_CONTROL);
	header_.arm11_local.other_user_save_ids = le_dword(saveIds);

	return 0;
}

int CxiExtendedHeader::SetAccessibleSaveIds(const std::vector<u32>& ids, bool use_other_variation_save_data)
{
	if (ids.size() > 6)
	{
		die("[ERROR] Too many AccessibleSaveIds. (Maximum 6)");
	}

	u64 extdata_id = 0;
	u64 other_user_save_ids = 0;

	// first three ids are written to other_user_save_ids
	for (u32 i = 0; i < ids.size() && i < 3; i++)
	{
		other_user_save_ids = (other_user_save_ids << 20) | (ids[i] & 0xffffff);
	}

	// final three ids are written to extdata_id
	for (u32 i = 3; i < ids.size() && i < 6; i++)
	{
		extdata_id = (extdata_id << 20) | (ids[i] & 0xffffff);
	}

	// set bit60 if use_other_variation_save_data
	if (use_other_variation_save_data)
	{
		other_user_save_ids |= BIT(60);
	}

	header_.arm11_local.extdata_id = le_dword(extdata_id);
	header_.arm11_local.other_user_save_ids = le_dword(other_user_save_ids);
	header_.arm11_local.fs_rights |= le_dword(USE_EXTENDED_SAVEDATA_ACCESS_CONTROL);

	return 0;
}

void CxiExtendedHeader::SetArm11FsRights(u64 rights)
{
	header_.arm11_local.fs_rights |= le_dword(rights & 0x00ffffffffffffff);
}

void CxiExtendedHeader::SetUseRomfs(bool use_romfs)
{
	if (!use_romfs)
		header_.arm11_local.fs_rights |= le_dword(NOT_USE_ROMFS);
}

int CxiExtendedHeader::SetServiceList(const std::vector<std::string>& service_list)
{
	if (service_list.size() > kMaxServiceNum)
	{
		die("[ERROR] Too many services. (Maximum 34)");
	}

	if (service_list.size() > 32)
	{
		fprintf(stderr, "[WARNING] Service \"%s\" will not be available on firmwares <= 9.3.0\n", service_list[32].c_str());
	}
	if (service_list.size() > 33)
	{
		fprintf(stderr, "[WARNING] Service \"%s\" will not be available on firmwares <= 9.3.0\n", service_list[33].c_str());
	}

	for (u32 i = 0; i < service_list.size() && i < kMaxServiceNum; i++)
	{
		strncpy(header_.arm11_local.service_list[i], service_list[i].c_str(), 8);
	}

	return 0;
}

void CxiExtendedHeader::SetMaxCpu(u16 max_cpu)
{
	header_.arm11_local.resource_limit_descriptors[0] = le_hword(max_cpu);
}

void CxiExtendedHeader::SetResourceLimitCategory(ResourceLimitCategory category)
{
	header_.arm11_local.resource_limit_category = (u8)category;
}


// Set Arm11 Kernel Capabilities
inline u32 make_kernel_capability(u32 prefix, u32 value)
{
	return prefix | ((value) & ~prefix);
}

void CxiExtendedHeader::SetAllowedInterupts(const std::vector<u8>& interupt_list)
{
	u32 desc[8] = {0};
	u32 i, j;
	for (i = j = 0; j < interupt_list.size() && i < kMaxInteruptNum; i++, j++)
	{
		while (interupt_list[j] > kMaxInteruptValue && j < interupt_list.size())
		{
			j++;
		}
		if (j >= interupt_list.size())
		{
			break;
		}

		// if this is a new desc, set all bits
		if (i % 4)
		{
			desc[i/4] = 0xffffffff;
		}

		// shift the desc 7 bits
		desc[i/4] = (desc[i/4] << 7) | interupt_list[j];
	}
	for (i = 0; i < 8; i++)
	{
		if (desc[i] > 0)
		{
			allowed_interupts_.push_back(make_kernel_capability(INTERUPT_LIST, desc[i]));
		}
	}
}

void CxiExtendedHeader::SetAllowedSupervisorCalls(const std::vector<u8>& svc_list)
{
	u32 desc[8] = {0}; 
	for (u32 i = 0; i < svc_list.size(); i++)
	{
		if (svc_list[i] > kMaxSvcValue)
		{
			continue;
		}

		desc[(svc_list[i]/24)] |= 1 << ((svc_list[i] % 24) & 31);
	}
	for (u32 i = 0; i < 8; i++)
	{
		if (desc[i] > 0)
		{
			allowed_supervisor_calls_.push_back(make_kernel_capability(SVC_LIST | (i << 24), desc[i]));
		}
	}
}

void CxiExtendedHeader::SetReleaseKernelVersion(u16 version)
{
	if (version == 0) return;

	release_kernel_version_ = make_kernel_capability(KERNEL_RELEASE_VERSION, version);
}

void CxiExtendedHeader::SetHandleTableSize(u16 size)
{
	handle_table_size_ = make_kernel_capability(HANDLE_TABLE_SIZE, size);
}

void CxiExtendedHeader::SetMemoryType(MemoryType type)
{
	kernel_flags_ &= ~(0x00000f00);
	kernel_flags_ |= ((type << 8) & 0x00000f00);
	kernel_flags_ = make_kernel_capability(KERNEL_FLAG, kernel_flags_);
}

void CxiExtendedHeader::SetKernelFlags(u32 flags)
{
	kernel_flags_ &= ~(0x00fff0ff);
	kernel_flags_ |= (flags & 0x00fff0ff);
	kernel_flags_ = make_kernel_capability(KERNEL_FLAG, kernel_flags_);
}

inline u32 make_mapping_desc(u32 prefix, u32 address, bool is_read_only)
{
	return make_kernel_capability(prefix, (address >> 12) | (is_read_only << 20));
}

inline u32 align_to_page(u32 address)
{
	return (address & 0xFFF)? (address & ~0xFFF) + 0x1000 : address;
}

void CxiExtendedHeader::SetStaticMapping(const std::vector<struct sMemoryMapping>& mapping_list)
{
	// todo: be more strict?
	for (size_t i = 0; i < mapping_list.size(); i++)
	{
		if (mapping_list[i].start == 0)
		{
			continue;
		}

		// if the end offset is valid
		if (align_to_page(mapping_list[i].end) > mapping_list[i].start)
		{
			static_mappings_.push_back(make_mapping_desc(MAPPING_STATIC, mapping_list[i].start, mapping_list[i].is_read_only));
			static_mappings_.push_back(make_mapping_desc(MAPPING_STATIC, align_to_page(mapping_list[i].end), true));
		}
		else 
		{
			static_mappings_.push_back(make_mapping_desc(MAPPING_STATIC, mapping_list[i].start, mapping_list[i].is_read_only));
			static_mappings_.push_back(make_mapping_desc(MAPPING_STATIC, mapping_list[i].start + 0x1000, true));
		}
		
	}
}

void CxiExtendedHeader::SetIOMapping(const std::vector<struct sMemoryMapping>& mapping_list)
{
	// todo: be more strict?
	for (size_t i = 0; i < mapping_list.size(); i++)
	{
		if (mapping_list[i].start == 0)
		{
			continue;
		}

		// if the end offset is valid
		if (align_to_page(mapping_list[i].end) > mapping_list[i].start)
		{
			io_register_mappings_.push_back(make_mapping_desc(MAPPING_STATIC, mapping_list[i].start, false));
			io_register_mappings_.push_back(make_mapping_desc(MAPPING_STATIC, align_to_page(mapping_list[i].end), false));
		}
		else
		{
			io_register_mappings_.push_back(make_mapping_desc(MAPPING_IO, mapping_list[i].start, false));
		}
	}
}


// Set Arm9 Access Control
void CxiExtendedHeader::SetArm9IOControl(u32 io_rights, u8 descVersion)
{
	header_.arm9.io_rights = le_word(io_rights);
	header_.arm9.version = descVersion;
}

// commit the kernel descriptors to exheader
int CxiExtendedHeader::CommitArm11KernelCapabilities()
{
	u32 pos, i;

	// return error if there are more than kMaxKernelDescNum descriptors
	if ((allowed_supervisor_calls_.size() \
		+ allowed_interupts_.size() \
		+ io_register_mappings_.size() \
		+ static_mappings_.size() \
		+ (kernel_flags_ > 0) \
		+ (handle_table_size_ > 0) \
		+ (release_kernel_version_ > 0)) \
		> kMaxKernelDescNum)
	{
		die("[ERROR] Too many kernel descriptors");
	}

	pos = 0;

	for (i = 0; i < allowed_supervisor_calls_.size() && pos < kMaxKernelDescNum; i++)
	{
		header_.arm11_kernel.descriptors[pos++] = le_word(allowed_supervisor_calls_[i]);
	}

	for (i = 0; i < allowed_interupts_.size() && pos < kMaxKernelDescNum; i++)
	{
		header_.arm11_kernel.descriptors[pos++] = le_word(allowed_interupts_[i]);
	}

	for (i = 0; i < io_register_mappings_.size() && pos < kMaxKernelDescNum; i++)
	{
		header_.arm11_kernel.descriptors[pos++] = le_word(io_register_mappings_[i]);
	}

	for (i = 0; i < static_mappings_.size() && pos < kMaxKernelDescNum; i++)
	{
		header_.arm11_kernel.descriptors[pos++] = le_word(static_mappings_[i]);
	}

	if (kernel_flags_ > 0 && pos < kMaxKernelDescNum)
	{
		header_.arm11_kernel.descriptors[pos++] = kernel_flags_; 
	}

	if (handle_table_size_ > 0 && pos < kMaxKernelDescNum)
	{
		header_.arm11_kernel.descriptors[pos++] = handle_table_size_; 
	}

	if (release_kernel_version_ > 0 && pos < kMaxKernelDescNum)
	{
		header_.arm11_kernel.descriptors[pos++] = release_kernel_version_; 
	}

	// write dummy data to remaining descriptors
	for (; pos < kMaxKernelDescNum; pos++)
	{
		header_.arm11_kernel.descriptors[pos] = 0xffffffff;
	}

	return 0;
}
