#pragma once
#include "YamlReader.h"
#include "cxi_extended_header.h"

class CxiOptions
{
public:
	CxiOptions();
	~CxiOptions();

	/* Set Methods */
	int ParseSpecFile(const char* spec_file);

	void SetProductCode(const char* product_code);
	void SetMakerCode(const char* maker_code);
	void SetTitleId(u64 title_id);
	void SetProgramId(u64 program_id);

	void SetAppTitle(const char* app_title);
	void SetIsCompressCode(bool compress);
	void SetIsSdmcTitle(bool sdmc_title);
	void SetRemasterVersion(u16 version);
	void SetStackSize(u32 size);
	void SetSaveDataSize(u32 size);
	void SetJumpId(u64 jump_id);
	void SetDependencies(const std::vector<u64>& ids);
	int AddDependency(u64 title_id);

	void SetFirmwareTitleId(u64 title_id);
	void SetEnableL2Cache(bool enable);
	void SetEnableCpuSpeedUp(bool enable);
	void SetSnakeSystemMode(CxiExtendedHeader::SystemModeExt mode);
	void SetIdealProcessor(u8 processor);
	void SetProcessAffinityMask(u8 affinity_mask);
	void SetCtrSystemMode(CxiExtendedHeader::SystemMode mode);
	void SetProcessPriority(int8_t priority);
	void SetUseExtdata(bool use_extdata);
	void SetExtdataId(u64 id);
	void SetSystemSaveIds(const std::vector<u32>& ids);
	void AddSystemSaveId(u32 save_id);
	void SetUseOtherVariationSave(bool enable);
	void SetOtherUserSaveIds(const std::vector<u32>& ids);
	void AddOtherUserSaveId(u32 save_id);
	void SetAccessibleSaveIds(const std::vector<u32>& ids);
	void AddAccessibleSaveId(u32 save_id);
	void SetServiceList(const std::vector<std::string>& services);
	int AddService(const std::string& service);
	void SetArm11FsAccessRights(u32 rights);
	void AddArm11FsAccessRight(CxiExtendedHeader::Arm11FsRight right);
	void SetMaxCpu(u16 max_cpu);
	void SetResourceLimitCategory(CxiExtendedHeader::ResourceLimitCategory category);

	void SetInterupts(const std::vector<u8>& interupts);
	void AddInterupt(u8 interupt);
	void SetSvcCalls(const std::vector<u8>& calls);
	void AddSvcCall(u8 call);
	void SetMinKernelVersion(u8 major, u8 minor);
	void SetHandleTableSize(u16 size);
	void SetMemoryType(CxiExtendedHeader::MemoryType type);
	void SetKernelFlags(u32 flags);
	void AddKernelFlag(u32 flag);
	void SetStaticMappings(const std::vector<CxiExtendedHeader::sMemoryMapping>& mappings);
	void AddStaticMapping(const CxiExtendedHeader::sMemoryMapping& mapping);
	void SetIOMappings(const std::vector<CxiExtendedHeader::sMemoryMapping>& mappings);
	void AddIOMapping(const CxiExtendedHeader::sMemoryMapping& mapping);
	
	void SetArm9FsAccessRights(u32 rights);
	void AddArm9FsAccessRight(CxiExtendedHeader::Arm9FsRight right);

	void SetArm9DescVersion(u8 version);

	/* Get Methods */
	inline const char* product_code() const { return product_code_; }
	inline const char* maker_code() const { return maker_code_; }
	inline u64 title_id() const { return title_id_; }
	inline u64 program_id() const { return program_id_; }

	inline const char* app_title() const { return app_title_; }
	inline bool is_compressed_code() const { return is_compressed_code_; }
	inline bool is_sdmc_title() const { return is_sdmc_title_; }
	inline u16 remaster_version() const { return remaster_version_; }
	inline u32 stack_size() const { return stack_size_; }
	inline u32 save_data_size() const { return save_data_size_; }
	inline u64 jump_id() const { return jump_id_; }
	inline const std::vector<u64>& dependency_list() const { return dependency_list_; }

	inline u64 firmware_title_id() const { return firmware_title_id_; }
	inline bool enable_l2_cache() const { return enable_l2_cache_; }
	inline CxiExtendedHeader::CpuSpeed cpu_speed() const { return cpu_speed_; }
	inline CxiExtendedHeader::SystemModeExt system_mode_ext() const { return system_mode_ext_; }
	inline u8 ideal_processor() const { return ideal_processor_; }
	inline u8 affinity_mask() const { return affinity_mask_; }
	inline CxiExtendedHeader::SystemMode system_mode() const { return system_mode_; }
	inline int8_t priority() const { return priority_; }
	inline bool use_extdata() const { return use_extdata_; }
	inline u64 extdata_id() const { return extdata_id_; }
	inline const std::vector<u32>& system_save_ids() const { return system_save_ids_; }
	inline bool use_variation_save() const { return use_variation_save_; }
	inline const std::vector<u32>& other_user_save_ids() const { return other_user_save_ids_; }
	inline const std::vector<u32>& accessible_save_ids() const { return accessible_save_ids_; }
	inline const std::vector<std::string>& services() const { return services_; }
	inline u64 arm11_fs_access() const { return arm11_fs_access_; }
	inline u16 max_cpu() const { return max_cpu_; }
	inline CxiExtendedHeader::ResourceLimitCategory resource_limit_category() const { return resource_limit_category_; }

	inline const std::vector<u8>& interupts() const { return interupts_; }
	inline const std::vector<u8>& svc_calls() const { return svc_calls_; }
	inline u16 min_kernel_version() const { return (min_kernel_version_[0] << 8) | (min_kernel_version_[1] << 0); }
	inline u16 handle_table_size() const { return handle_table_size_; }
	inline CxiExtendedHeader::MemoryType memory_type() const { return memory_type_; }
	inline u32 kernel_flags() const { return kernel_flags_; }
	inline const std::vector<CxiExtendedHeader::sMemoryMapping>& static_mappings() const { return static_mappings_; }
	inline const std::vector<CxiExtendedHeader::sMemoryMapping>& io_mappings() const { return io_mappings_; }
	
	inline u32 arm9_fs_access() const { return arm9_fs_access_; }
	inline u8 arm9_desc_version() const { return desc_version_; }
private:
	char product_code_[16];
	char maker_code_[2];
	u64 title_id_;
	u64 program_id_;

	// process info
	char app_title_[8];
	bool is_compressed_code_;
	bool is_sdmc_title_;
	u16 remaster_version_;
	u32 stack_size_;
	u32 save_data_size_;
	u64 jump_id_;
	std::vector<u64> dependency_list_;


	// arm11 userland system
	u64 firmware_title_id_;
	bool enable_l2_cache_;
	CxiExtendedHeader::CpuSpeed cpu_speed_;
	CxiExtendedHeader::SystemModeExt system_mode_ext_;
	u8 ideal_processor_;
	u8 affinity_mask_;
	CxiExtendedHeader::SystemMode system_mode_;
	int8_t priority_;
	bool use_extdata_;
	u64 extdata_id_;
	std::vector<u32> system_save_ids_;
	bool use_variation_save_;
	std::vector<u32> other_user_save_ids_;
	std::vector<u32> accessible_save_ids_;
	std::vector<std::string> services_;
	u64 arm11_fs_access_;
	u16 max_cpu_;
	CxiExtendedHeader::ResourceLimitCategory resource_limit_category_;

	// arm11 kern
	std::vector<u8> interupts_;
	std::vector<u8> svc_calls_;
	u8 min_kernel_version_[2];
	u16 handle_table_size_;
	CxiExtendedHeader::MemoryType memory_type_;
	u32 kernel_flags_;
	std::vector<CxiExtendedHeader::sMemoryMapping> static_mappings_;
	std::vector<CxiExtendedHeader::sMemoryMapping> io_mappings_;

	// arm9
	u32 arm9_fs_access_;
	u8 desc_version_;

	void SetDefaults();

	int EvaluateBooleanString(bool& dst, const std::string& str);
	int AddDependency(const std::string& dependency_str);
	int ParseSpecFileProccessConfig(YamlReader& spec);
	int SetSaveDataSize(std::string& size_str);
	int ParseSpecFileSaveData(YamlReader& spec);

	//int AddService(const std::string& service_str);
	int AddIOMapping(const std::string& mapping_str);
	int AddStaticMapping(const std::string& mapping_str);
	int AddFSAccessRight(const std::string& right_str);
	int AddKernelFlag(const std::string& flag_str);
	int AddArm9AccessRight(const std::string& right_str);
	int ParseSpecFileRights(YamlReader& spec);
};
