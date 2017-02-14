#pragma once
#include <fnd/types.h>
#include <crypto/crypto.h>
#include <ctr/extended_header.h>
#include <ctr/arm11_local_caps.h>
#include <ctr/arm11_kernel_caps.h>
#include <ctr/arm9_access_control.h>

class AccessDescriptor
{
public:
	AccessDescriptor();
	AccessDescriptor(const u8* data);
	AccessDescriptor(const AccessDescriptor& other);
	~AccessDescriptor();

	void operator=(const AccessDescriptor& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData(const Crypto::sRsa2048Key& accessdesc_rsa_key);
	void SetDataUsingExtendedheader(const ExtendedHeader& exheader);
	void SetNcchRsaKey(const Crypto::sRsa2048Key& rsa_key);
	void SetArm11LocalCaps(const Arm11LocalCaps& arm11_local);
	void SetArm11KernelCaps(const Arm11KernelCaps& arm11_kernel);
	void SetArm9AccessControl(const Arm9AccessControl& arm9);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	bool ValidateSignature(const Crypto::sRsa2048Key& accessdesc_rsa_key) const;
	const Crypto::sRsa2048Key& GetNcchRsaKey() const;
	const Arm11LocalCaps& GetArm11LocalCaps() const;
	const Arm11KernelCaps& GetArm11KernelCaps() const;
	const Arm9AccessControl& GetArm9AccessControl() const;

	// Exheader Validation
	void ValidateExtendedHeader(const ExtendedHeader& exheader);
	bool IsExheaderValid() const;
	// arm11 local caps
	bool IsProgramIdValid() const;
	bool IsFirmwareTitleIdValid() const;
	bool IsEnableL2CacheValid() const;
	bool IsCpuSpeedValid() const;
	bool IsSystemModeExtValid() const;
	bool IsIdealProcessorValid() const;
	bool IsAffinityMaskValid() const;
	bool IsSystemModeValid() const;
	bool IsThreadPriorityValid() const;
	bool IsSystemSaveId1Valid() const;
	bool IsSystemSaveId2Valid() const;
	bool IsFsRightsValid() const;
	bool IsServiceACLValid() const;

	// arm11 kernel caps
	bool IsInterruptACLValid() const;
	bool IsSystemCallACLValid() const;
	bool IsHandleTableSizeValid() const;
	bool IsKernelFlagsValid() const;
	bool IsMemoryTypeValid() const;
	bool IsMemoryMappingValid() const;
	bool IsIORegisterMappingValid() const;

	// arm9 access control
	bool IsIORightsValid() const;
	bool IsDescVersionValid() const;

private:
	const std::string kModuleName = "ACCESS_DESCRIPTOR";
	static const size_t kArm11LocalCapsSize = 0x170;
	static const size_t kArm11KernelCapsSize = 0x80;
	static const size_t kArm9AccessControlSize = 0x10;

	// Private Structures
#pragma pack (push, 1)
	struct sAccessDescriptor
	{
		u8 rsa_signature[Crypto::kRsa2048Size];
		struct sBody
		{
			u8 ncch_rsa_public_key[Crypto::kRsa2048Size];
			u8 arm11_local_caps[kArm11LocalCapsSize];
			u8 arm11_kernel_caps[kArm11KernelCapsSize];
			u8 arm9_access_control[kArm9AccessControlSize];
		} body;
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	Crypto::sRsa2048Key ncch_public_key_;
	Arm11LocalCaps arm11_local_caps_;
	Arm11KernelCaps arm11_kernel_caps_;
	Arm9AccessControl arm9_access_control_;

	bool valid_at_all_;
	bool valid_program_id_;
	bool valid_firmware_id_;
	bool valid_l2_cache_state_;
	bool valid_cpu_speed_;
	bool valid_system_mode_ext_;
	bool valid_ideal_processor_;
	bool valid_affinity_mask_;
	bool valid_system_mode_;
	bool valid_thread_priority_;
	bool valid_system_save_id_[2];
	bool valid_fs_rights_;
	bool valid_service_acl_;
	bool valid_interrupt_acl_;
	bool valid_system_call_acl_;
	bool valid_handle_table_size_;
	bool valid_kernel_flags_;
	bool valid_memory_type_;
	bool valid_memory_mapping_;
	bool valid_io_register_mapping_;
	bool valid_io_rights_;
	bool valid_desc_version_;

	template<typename T>
	void CheckWhiteList(const std::vector<T>& list, const std::vector<T>& white_list, bool& is_valid)
	{
		is_valid = true;
		for (size_t i = 0; i < list.size(); i++)
		{
			bool found = false;
			for (size_t j = 0; j < white_list.size() && found == false; j++)
			{
				found = list[i] == white_list[j];
			}

			if (found == false)
			{
				valid_at_all_ = false;
				is_valid = false;
				break;
			}
		}
	}



	bool CheckMapInRange(const Arm11KernelCaps::sMemoryMapping& map, const Arm11KernelCaps::sMemoryMapping& range);
	void CheckMappingRangeWhiteList(const std::vector<Arm11KernelCaps::sMemoryMapping>& maps, const std::vector<Arm11KernelCaps::sMemoryMapping>& white_list, bool& is_valid);

	void CheckProgramId(u64 program_id);
	void CheckFirmwareTitleId(u64 title_id);
	void CheckEnableL2Cache(bool is_enabled);
	void CheckCpuSpeed(Arm11LocalCaps::CpuSpeed cpu_speed);
	void CheckSystemModeExt(Arm11LocalCaps::SystemModeExt system_mode);
	void CheckIdealProcessor(u8 ideal_processor);
	void CheckAffinityMask(u8 affinity_mask);
	void CheckSystemMode(Arm11LocalCaps::SystemMode system_mode);
	void CheckThreadPriority(int8_t priority);
	void CheckSystemSaveIds(u32 id1, u32 id2);
	void CheckFsRights(const std::vector<Arm11LocalCaps::FSRight>& right_list);
	void CheckServiceACL(const std::vector<std::string>& service_list);
	void CheckSystemCallACL(const std::vector<u8>& system_call_list);
	void CheckInterruptListACL(const std::vector<u8>& interrupt_list);
	void CheckHandleTableSize(u32 size);
	void CheckKernelFlags(const std::vector<Arm11KernelCaps::KernelFlag>& flags);
	void CheckMemoryType(Arm11KernelCaps::MemoryType memory_type);
	void CheckMemoryMapping(const std::vector<Arm11KernelCaps::sMemoryMapping>& maps);
	void CheckIORegisterMapping(const std::vector<Arm11KernelCaps::sMemoryMapping>& maps);
	void CheckIORights(const std::vector<Arm9AccessControl::IORight>& right_list);
	void CheckDescVersion(u8 version);

	void ClearDeserialisedVariables();
};

