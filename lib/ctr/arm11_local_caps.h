#pragma once
#include <string>
#include <vector>
#include <fnd/types.h>
#include <fnd/memory_blob.h>
#include <ctr/ctr_program_id.h>

class Arm11LocalCaps
{
public:
	// Public Enums
	enum CpuSpeed
	{
		CLOCK_268MHz,
		CLOCK_804MHz
	};

	enum SystemMode
	{
		SYSMODE_PROD,
		SYSMODE_UNSUPPORTED,
		SYSMODE_DEV1,
		SYSMODE_DEV2,
		SYSMODE_DEV3,
		SYSMODE_DEV4
	};

	enum SystemModeExt
	{
		SYSMODE_SNAKE_LEGACY,
		SYSMODE_SNAKE_PROD,
		SYSMODE_SNAKE_DEV1,
		SYSMODE_SNAKE_DEV2
	};

	enum ResourceLimitCategory
	{
		RESLIMIT_APPLICATION,
		RESLIMIT_SYS_APPLET,
		RESLIMIT_LIB_APPLET,
		RESLIMIT_OTHER
	};

	enum FSRight
	{
		ARM11_CATEGORY_SYSTEM_APPLICATION,
		ARM11_CATEGORY_HARDWARE_CHECK,
		ARM11_CATEGORY_FILE_SYSTEM_TOOL,
		ARM11_DEBUG,
		ARM11_TWL_CARD,
		ARM11_TWL_NAND,
		ARM11_BOSS,
		ARM11_DIRECT_SDMC,
		ARM11_CORE,
		ARM11_CTR_NAND_RO,
		ARM11_CTR_NAND_RW,
		ARM11_CTR_NAND_RO_WRITE,
		ARM11_CATEGORY_SYSTEM_SETTINGS,
		ARM11_CARD_BOARD,
		ARM11_EXPORT_IMPORT_IVS,
		ARM11_DIRECT_SDMC_WRITE,
		ARM11_SWITCH_CLEANUP,
		ARM11_SAVE_DATA_MOVE,
		ARM11_SHOP,
		ARM11_SHELL,
		ARM11_CATEGORY_HOME_MENU,
		ARM11_EXTERNAL_SEED,
	};

	// Constructor/Destructor
	Arm11LocalCaps();
	Arm11LocalCaps(const u8* data);
	Arm11LocalCaps(const Arm11LocalCaps& other);
	~Arm11LocalCaps();

	void operator=(const Arm11LocalCaps& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData();
	void SetProgramId(u64 program_id);
	void SetFirmTitleId(u64 title_id);
	void EnableL2Cache(bool enable);
	void SetCpuSpeed(CpuSpeed speed);
	void SetSystemModeExt(SystemModeExt system_mode);
	void SetIdealProcessor(u8 ideal_processor);
	void SetAffinityMask(u8 affinity_mask);
	void SetSystemMode(SystemMode system_mode);
	void SetThreadPriority(int8_t priority);
	void SetMaxCpuTime(u16 max_time);
	void SetExtdataId(u64 extdata_id);
	void SetSystemSaveIds(u32 save_id1, u32 save_id2);
	void SetSystemSaveIds(const std::vector<u32>& id_list);
	void SetOtherUserSaveIds(u32 save_id1, u32 save_id2, u32 save_id3);
	void SetOtherUserSaveIds(const std::vector<u32>& id_list);
	void SetAccessibleSaveIds(const std::vector<u32>& id_list);
	void AllowAccessOtherVariationSaveData(bool allow);
	void SetFsRights(u64 fs_rights);
	void SetFsRights(const std::vector<FSRight>& fs_right_list);
	void AllowUseRomfs(bool allow);
	void SetServiceACL(const std::vector<std::string>& service_list);
	void SetResourceLimitCategory(ResourceLimitCategory category);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	u64 GetProgramId() const;
	u64 GetFirmTitleId() const;
	bool IsL2CacheEnabled() const;
	CpuSpeed GetCpuSpeed() const;
	SystemModeExt GetSystemModeExt() const;
	u8 GetIdealProcessor() const;
	u8 GetAffinityMask() const;
	SystemMode GetSystemMode() const;
	int8_t GetThreadPriority() const;
	u16 GetMaxCpuTime() const;
	u64 GetExtdataId() const;
	u32 GetSystemSaveId1() const;
	u32 GetSystemSaveId2() const;
	u32 GetOtherUserSaveId1() const;
	u32 GetOtherUserSaveId2() const;
	u32 GetOtherUserSaveId3() const;
	const std::vector<u32>& GetAccessibleSaveIds() const;
	bool CanAccessOtherVariationSaveData() const;
	u64 GetFsRights() const;
	const std::vector<FSRight>& GetFsRightList() const;
	bool HasFsRight(FSRight right);
	bool CanMountRomfs() const;
	const std::vector<std::string>& GetServiceACL() const;
	ResourceLimitCategory GetResourceLimitCategory() const;

private:
	const std::string kModuleName = "ARM11_LOCAL_CAPS";
	static const u32 kMaxServiceNum = 34;
	static const int kServiceNameMaxLen = 8;
	static const u32 kMaxResourceLimitNum = 16;
	static const u32 kSystemSaveIdNum = 2;
	static const u32 kOtherUserSaveIdNum = 3;
	static const u32 kMaxAccessibleSaveIdNum = 6;
	static const u32 k20BitIdMask = 0xfffff;
	static const u32 k20BitShift = 20;
	static const u64 kFsRightsMask = 0x00ffffffffffffff;
	static const u8 kMaxFsRight = 56;
	static const u8 kFsAttributeMask = 0xff;
	static const u8 kFsAttributeShift = 56;
	static const u8 kCanUseOtherVariationSaveBit = 60;
	static const u8 kMaxIdealProcessor = 3;
	static const u8 kMaxAffinityMask = 3;

	enum FSAttributes
	{
		NOT_USE_ROMFS,
		USE_EXTENDED_SAVEDATA_ACCESS_CONTROL,
	};

	static inline u64 write_u64(u64 src, u64 data, u64 mask, u8 bitpos) { return (src & ~(mask << bitpos)) | (data & mask) << bitpos; }
	static inline u64 read_u64(u64 src, u64 mask, u8 bitpos) { return (src >> bitpos) & mask; }
	
	
	// Private Structures
#pragma pack (push, 1)
	struct sArm11LocalCapabilities
	{
	private:
		u64 program_id_;
		u32 firm_title_id_low_;
		union
		{
			u8 flag_[4];
			struct
			{
				u8 enable_l2_cache_ : 1;
				u8 cpu_speed_ : 1;
				u8 reserved0: 6;

				u8 system_mode_ext_ : 4;
				u8 reserved1: 4;

				u8 ideal_processor_ : 2;
				u8 affinity_mask_ : 2;
				u8 system_mode_ : 4;

				int8_t thread_priority_;
			};
		};
		u16 resource_limit_descriptors_[kMaxResourceLimitNum];

		u64 extdata_id_;
		u32 system_save_ids_[kSystemSaveIdNum];
		u64 other_user_save_ids_;
		u64 fs_rights_;
		char service_list_[kMaxServiceNum][kServiceNameMaxLen];
		u8 reserved2[0xf];
		u8 resource_limit_category_;
	public:
		u64 program_id() const { return le_dword(program_id_); }
		u64 firm_title_id() const { return CtrProgramId::make_ctr_id(CtrProgramId::CATEGORY_FIRMWARE, 0, 0) | le_word(firm_title_id_low_); }
		bool is_l2_cache_enabled() const { return enable_l2_cache_; }
		CpuSpeed cpu_speed() const { return (CpuSpeed)cpu_speed_; }
		SystemModeExt system_mode_ext() const { return (SystemModeExt)system_mode_ext_; }
		u8 ideal_processor() const { return ideal_processor_; }
		u8 affinity_mask() const { return affinity_mask_; }
		SystemMode system_mode() const { return (SystemMode)system_mode_; }
		int8_t thread_priority() const { return thread_priority_; }
		u16 resource_limit_descriptor(int index) const { return le_hword(resource_limit_descriptors_[index]); }
		u64 extdata_id() const { return le_dword(extdata_id_); }
		u32 system_save_id(int index) const { return le_word(system_save_ids_[index]); }
		u32 other_user_save_id(int index) const { return read_u64(le_dword(other_user_save_ids_), k20BitIdMask, k20BitShift * (2-index)); }
		bool use_other_variation_save_data() const { return le_dword(other_user_save_ids_) & (u64)BIT(kCanUseOtherVariationSaveBit); }
		u32 accessible_save_id(int index) const { return index < 3? other_user_save_id(index) : read_u64(le_dword(extdata_id_), k20BitIdMask, k20BitShift * (2 + 3 - index)); }
		u64 fs_rights() const { return read_u64(le_dword(fs_rights_), kFsRightsMask, 0); }
		bool fs_rights_has_bit(u8 bit) const { return (fs_rights() & BIT(bit)) == BIT(bit); }
		u8 fs_attibutes() const { return read_u64(le_dword(fs_rights_), kFsAttributeMask, kFsAttributeShift); }
		bool fs_attribute_has_bit(u8 bit) const { return (fs_attibutes() & BIT(bit)) == BIT(bit); }
		const char* service(int index) const { return service_list_[index]; }
		ResourceLimitCategory resource_limit_category() const { return (ResourceLimitCategory)resource_limit_category_; }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_program_id(u64 program_id) { program_id_ = le_dword(program_id); }
		void set_firm_title_id(u64 title_id) { firm_title_id_low_ = le_word((u32)title_id); }
		void set_enable_l2_cache(bool enable) { enable_l2_cache_ = enable; }
		void set_cpu_speed(CpuSpeed speed) { cpu_speed_ = speed; }
		void set_system_mode_ext(SystemModeExt system_mode) { system_mode_ext_ = system_mode; }
		void set_ideal_processor(u8 ideal_processor) { ideal_processor_ = ideal_processor; }
		void set_affinity_mask(u8 affinity_mask) { affinity_mask_ = affinity_mask; }
		void set_system_mode(SystemMode system_mode) { system_mode_ = system_mode; }
		void set_thread_priority(int8_t priority) { thread_priority_ = priority; }
		void set_resource_limit_descriptor(int index, u16 desc) { resource_limit_descriptors_[index] = le_hword(desc); }
		void set_extdata_id(u64 extdata_id) { extdata_id_ = le_dword(extdata_id); }
		void set_system_save_id(int index, u32 save_id) { system_save_ids_[index] = le_word(save_id); }
		void set_other_user_save_id(int index, u32 save_id) { other_user_save_ids_ = le_dword(write_u64(le_dword(other_user_save_ids_), save_id, k20BitIdMask, k20BitShift * (2 - index))); }
		void set_use_other_variation_save_data(bool allowed) { other_user_save_ids_ = le_dword(write_u64(le_dword(other_user_save_ids_), allowed, 1, kCanUseOtherVariationSaveBit));}
		void set_accessible_save_id(int index, u32 save_id) 
		{ 
			if (index < 3)
				set_other_user_save_id(index, save_id);
			else
				extdata_id_ = le_dword(write_u64(le_dword(extdata_id_), save_id, k20BitIdMask, k20BitShift * (2 + 3 - index))); 
		}
		void set_fs_rights(u64 rights) { fs_rights_ = le_dword(write_u64(le_dword(fs_rights_), rights, kFsRightsMask, 0)); }
		void set_fs_right_bit(u8 bit, bool set) { fs_rights_ = le_dword(write_u64(le_dword(fs_rights_), set, 1, bit)); }
		void set_fs_attributes(u8 attributes) { fs_rights_ = le_dword(write_u64(le_dword(fs_rights_), attributes, kFsAttributeMask, kFsAttributeShift)); }
		void set_fs_attribute_bit(u8 bit, bool set) { fs_rights_ = le_dword(write_u64(le_dword(fs_rights_), set, 1, bit + kFsAttributeShift)); }
		void set_service(int index, const char* name) { strncpy(service_list_[index], name, kServiceNameMaxLen); }
		void set_resource_limit_category(ResourceLimitCategory category) { resource_limit_category_ = category; }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	u64 program_id_;
	u64 firm_title_id_;

	bool is_l2_cache_enabled_;
	CpuSpeed cpu_speed_;
	SystemModeExt system_mode_ext_;

	u8 ideal_processor_;
	u8 affinity_mask_;
	SystemMode system_mode_;

	int8_t thread_priority_;
	
	u16 max_cpu_time_;

	u64 extdata_id_;
	u32 system_save_id_[kSystemSaveIdNum];
	u32 other_user_save_id_[kOtherUserSaveIdNum];
	bool use_other_variation_save_data_;
	std::vector<u32> accessible_save_ids_;
	u64 fs_rights_;
	std::vector<FSRight> fs_right_list_;
	bool mount_romfs_;
	std::vector<std::string> service_acl_;
	ResourceLimitCategory resource_limit_category_;

	void ClearDeserialisedVariables();
};

