#pragma once
#include <vector>
#include <string>
#include "types.h"
#include "crypto.h"

#include "program_id.h"

class CxiExtendedHeader
{
public:
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

	enum MemoryType
	{
		MEMTYPE_APPLICATION = 1,
		MEMTYPE_SYSTEM = 2,
		MEMTYPE_BASE = 3
	};

	enum ResourceLimitCategory
	{
		RESLIMIT_APPLICATION,
		RESLIMIT_SYS_APPLET,
		RESLIMIT_LIB_APPLET,
		RESLIMIT_OTHER
	};

	enum Arm11FsRight
	{
		ARM11_CATEGORY_SYSTEM_APPLICATION = BIT(0),
		ARM11_CATEGORY_HARDWARE_CHECK = BIT(1),
		ARM11_CATEGORY_FILE_SYSTEM_TOOL = BIT(2),
		ARM11_DEBUG = BIT(3),
		ARM11_TWL_CARD = BIT(4),
		ARM11_TWL_NAND = BIT(5),
		ARM11_BOSS = BIT(6),
		ARM11_DIRECT_SDMC = BIT(7),
		ARM11_CORE = BIT(8),
		ARM11_CTR_NAND_RO = BIT(9),
		ARM11_CTR_NAND_RW = BIT(10),
		ARM11_CTR_NAND_RO_WRITE = BIT(11),
		ARM11_CATEGORY_SYSTEM_SETTINGS = BIT(12),
		ARM11_CARD_BOARD = BIT(13),
		ARM11_EXPORT_IMPORT_IVS = BIT(14),
		ARM11_DIRECT_SDMC_WRITE = BIT(15),
		ARM11_SWITCH_CLEANUP = BIT(16),
		ARM11_SAVE_DATA_MOVE = BIT(17),
		ARM11_SHOP = BIT(18),
		ARM11_SHELL = BIT(19),
		ARM11_CATEGORY_HOME_MENU = BIT(20),
		ARM11_EXTERNAL_SEED = BIT(21),
	};

	enum KernelFlag
	{
		KERNFLAG_PERMIT_DEBUG = BIT(0),
		KERNFLAG_FORCE_DEBUG = BIT(1),
		KERNFLAG_CAN_USE_NON_ALPHABET_AND_NUMBER = BIT(2),
		KERNFLAG_CAN_WRITE_SHARED_PAGE = BIT(3),
		KERNFLAG_CAN_USE_PRIVILEGE_PRIORITY = BIT(4),
		KERNFLAG_PERMIT_MAIN_FUNCTION_ARGUMENT = BIT(5),
		KERNFLAG_CAN_SHARE_DEVICE_MEMORY = BIT(6),
		KERNFLAG_RUNNABLE_ON_SLEEP = BIT(7),
		KERNFLAG_SPECIAL_MEMORY_LAYOUT = BIT(12),
		KERNFLAG_CAN_ACCESS_CORE2 = BIT(13),
	};

	enum Arm9FsRight
	{
		ARM9_FS_MOUNT_NAND = BIT(0),
		ARM9_FS_MOUNT_NAND_RO_WRITE = BIT(1),
		ARM9_FS_MOUNT_TWLN = BIT(2),
		ARM9_FS_MOUNT_WNAND = BIT(3),
		ARM9_FS_MOUNT_CARD_SPI = BIT(4),
		ARM9_USE_SDIF3 = BIT(5),
		ARM9_CREATE_SEED = BIT(6),
		ARM9_USE_CARD_SPI = BIT(7),
		ARM9_SD_APPLICATION = BIT(8),
		ARM9_USE_DIRECT_SDMC = BIT(9),
	};

	struct sMemoryMapping
	{
		u32 start;
		u32 end;
		bool is_read_only;
	};

	CxiExtendedHeader();
	~CxiExtendedHeader();

	int CreateExheader(const Crypto::sRsa2048Key& ncch_rsa, const Crypto::sRsa2048Key& accessdesc_rsa);

	inline const u8* exheader_blob() const { return (const u8*)&header_; }
	inline u32 exheader_size() const { return sizeof(struct sExtendedHeader); }
	inline const u8* accessdesc_blob() const { return (const u8*)&access_descriptor_; }
	inline u32 accessdesc_size() const { return sizeof(struct sAccessDescriptor); }

	// for parsing exheader
	int SetData(const u8* exheader, const u8* accessdesc);

	// Set Process Info
	void SetProcessName(const char* name);
	void SetIsCodeCompressed(bool is_code_compressed);
	void SetIsSdmcTitle(bool is_sdmc_title);
	void SetRemasterVersion(u16 version);
	void SetTextSegment(u32 address, u32 page_num, u32 size);
	void SetRoDataSegment(u32 address, u32 page_num, u32 size);
	void SetDataSegment(u32 address, u32 page_num, u32 size);
	void SetStackSize(u32 stack_size);
	void SetBssSize(u32 bss_size);
	int SetDependencyList(const std::vector<u64>& dependency_list);
	void SetSaveDataSize(u32 size);
	void SetJumpId(u64 id);

	// Set Arm11 Local Capabilities
	void SetProgramId(u64 id);
	void SetFirmwareTitleId(u64 id);
	void SetEnableL2Cache(bool enable);
	void SetCpuSpeed(CpuSpeed speed);
	void SetSystemModeExt(SystemModeExt mode);
	int SetIdealProcessor(u8 processor);
	int SetProcessAffinityMask(u8 affinity_mask);
	void SetSystemMode(SystemMode mode);
	int SetProcessPriority(int8_t priority);
	void SetExtdataId(u64 id);
	int SetSystemSaveIds(const std::vector<u32>& ids);
	int SetOtherUserSaveIds(const std::vector<u32>& ids, bool use_other_variation_save_data);
	int SetAccessibleSaveIds(const std::vector<u32>& ids, bool use_other_variation_save_data);
	void SetArm11FsRights(u64 rights);
	void SetUseRomfs(bool use_romfs);
	int SetServiceList(const std::vector<std::string>& service_list);
	void SetMaxCpu(u16 max_cpu);
	void SetResourceLimitCategory(ResourceLimitCategory category);

	// Set Arm11 Kernel Capabilities
	void SetAllowedInterupts(const std::vector<u8>& interupt_list);
	void SetAllowedSupervisorCalls(const std::vector<u8>& svc_list);
	void SetReleaseKernelVersion(u16 version);
	void SetHandleTableSize(u16 size);
	void SetMemoryType(MemoryType type);
	void SetKernelFlags(u32 flags);
	void SetStaticMapping(const std::vector<struct sMemoryMapping>& mapping_list);
	void SetIOMapping(const std::vector<struct sMemoryMapping>& mapping_list);

	// Set Arm9 Access Control
	void SetArm9IOControl(u32 io_rights, u8 desc_version);

	// parse exheader
	inline const char* process_name() const { return header_.process_info.name; }
	inline bool is_code_compressed() const { return header_.process_info.is_code_compressed; }
	inline bool is_sdmc_title() const { return header_.process_info.is_sdmc_title; }
	inline u16 remaster_version() const { return le_hword(header_.process_info.remaster_version); }
	// code info
	inline u32 text_address() const { return le_word(header_.process_info.code_info.text.address); }
	inline u32 text_size() const { return le_word(header_.process_info.code_info.text.size); }
	inline u32 text_page_num() const { return le_word(header_.process_info.code_info.text.page_num); }
	inline u32 rodata_address() const { return le_word(header_.process_info.code_info.rodata.address); }
	inline u32 rodata_size() const { return le_word(header_.process_info.code_info.rodata.size); }
	inline u32 rodata_page_num() const { return le_word(header_.process_info.code_info.rodata.page_num); }
	inline u32 data_address() const { return le_word(header_.process_info.code_info.data.address); }
	inline u32 data_size() const { return le_word(header_.process_info.code_info.data.size); }
	inline u32 data_page_num() const { return le_word(header_.process_info.code_info.data.page_num); }
	inline u32 stack_size() const { return le_word(header_.process_info.code_info.stack_size); }
	inline u32 bss_size() const { return le_word(header_.process_info.code_info.bss_size); }
	
	inline u32 save_data_size() const { return le_word(header_.process_info.save_data_size); }
	inline u64 jump_id() const { return le_dword(header_.process_info.jump_id); }
	inline u64 program_id() const { return le_dword(header_.arm11_local.program_id); }
	inline u64 firm_title_id() const { return ProgramId::make_ctr_id(ProgramId::CATEGORY_FIRMWARE, 0, 0) | le_word(header_.arm11_local.firm_title_id_low); }
	inline bool is_enable_l2_cache() const { return header_.arm11_local.enable_l2_cache; }
	inline CpuSpeed cpu_speed() const { return header_.arm11_local.cpu_speed ? CpuSpeed::CLOCK_804MHz : CpuSpeed::CLOCK_268MHz; }
	inline SystemModeExt system_mode_ext() const { return (SystemModeExt)header_.arm11_local.system_mode_ext; }
	inline u8 ideal_processor() const { return header_.arm11_local.ideal_processor; }
	inline u8 affinity_mask() const { return header_.arm11_local.affinity_mask; }
	inline SystemMode system_mode() const { return (SystemMode)header_.arm11_local.system_mode; }


private:
	static const u32 kMaxInteruptNum = 32;
	static const u32 kMaxInteruptValue = 0x7F;
	static const u32 kMaxSvcValue = 0x7D;
	static const u32 kMaxDependencyNum = 0x30;
	static const u32 kMaxKernelDescNum = 28;
	static const u32 kMaxServiceNum = 34;
	static const u32 kMaxResourceLimitNum = 16;
	static const u32 kMaxSystemSaveIdNum = 2;

	enum FSAttributes
	{
		NOT_USE_ROMFS = BIT(56),
		USE_EXTENDED_SAVEDATA_ACCESS_CONTROL = BIT(57),
	};

	enum KernelCapabilityPrefix
	{
		INTERUPT_LIST = 0xe0000000,
		SVC_LIST = 0xf0000000,
		KERNEL_RELEASE_VERSION = 0xfc000000,
		HANDLE_TABLE_SIZE = 0xfe000000,
		KERNEL_FLAG = 0xff000000,
		MAPPING_STATIC = 0xff800000,
		MAPPING_IO = 0xffc00000,
	};

	struct sCodeSegmentInfo
	{
		u32 address;
		u32 page_num;
		u32 size;
	};

	struct sProcessInfo
	{
		char name[8];
		u8 reserved0[5];
		union
		{
			u8 flag;
			struct
			{
				u8 is_code_compressed : 1;
				u8 is_sdmc_title : 1;
			};
		};

		u16 remaster_version;

		struct sCodeInfo
		{
			struct sCodeSegmentInfo text;
			u32 stack_size;
			struct sCodeSegmentInfo rodata;
			u8 reserved1[4];
			struct sCodeSegmentInfo data;
			u32 bss_size;
		} code_info;
		
		u64 dependency_list[kMaxDependencyNum];

		u32 save_data_size;
		u8 reserved2[4];
		u64 jump_id;
		u8 reserved3[0x30];
	};

	struct sArm11LocalCapabilities
	{
		u64 program_id;
		u32 firm_title_id_low;
		union
		{
			u8 flag[4];
			struct
			{
				u8 enable_l2_cache : 1;
				u8 cpu_speed : 1;
				u8: 6;

				u8 system_mode_ext : 4;
				u8: 4;

				u8 ideal_processor : 2;
				u8 affinity_mask : 2;
				u8 system_mode : 4;

				int8_t thread_priority;
			};
		};
		u16 resource_limit_descriptors[kMaxResourceLimitNum];

		u64 extdata_id;
		u32 system_save_ids[kMaxSystemSaveIdNum];
		u64 other_user_save_ids;
		u64 fs_rights;
		char service_list[kMaxServiceNum][8];
		u8 reserved[0xf];
		u8 resource_limit_category;
	};

	struct sArm11KernelCapabilities
	{
		u32 descriptors[kMaxKernelDescNum];
		u8 reserved[0x10];
	};

	struct sArm9AccessControl
	{
		u32 io_rights;
		u8 reserved[0xB];
		u8 version;
	};

	struct sExtendedHeader
	{
		struct sProcessInfo process_info;
		struct sArm11LocalCapabilities arm11_local;
		struct sArm11KernelCapabilities arm11_kernel;
		struct sArm9AccessControl arm9;
	};

	struct sAccessDescriptor
	{
		u8 signature[Crypto::kRsa2048Size];
		u8 ncch_rsa_modulus[Crypto::kRsa2048Size];
		struct sArm11LocalCapabilities arm11_local;
		struct sArm11KernelCapabilities arm11_kernel;
		struct sArm9AccessControl arm9;
	};

	struct sExtendedHeader header_;
	struct sAccessDescriptor access_descriptor_;

	std::vector<u32> allowed_interupts_;
	std::vector<u32> allowed_supervisor_calls_;
	u32 release_kernel_version_;
	u32 handle_table_size_;
	u32 kernel_flags_;
	std::vector<u32> static_mappings_;
	std::vector<u32> io_register_mappings_;

	int CommitArm11KernelCapabilities();
};

