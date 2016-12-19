#pragma once
#include <vector>
#include <fnd/types.h>
#include <fnd/ByteBuffer.h>

class Arm11KernelCaps
{
public:
	// Public Enums/Structs
	enum KernelFlag
	{
		PERMIT_DEBUG,
		FORCE_DEBUG,
		CAN_USE_NON_ALPHABET_AND_NUMBER,
		CAN_WRITE_SHARED_PAGE,
		CAN_USE_PRIVILEGE_PRIORITY,
		PERMIT_MAIN_FUNCTION_ARGUMENT,
		CAN_SHARE_DEVICE_MEMORY,
		RUNNABLE_ON_SLEEP,
		MEMORY_TYPE_RESERVED_0,
		MEMORY_TYPE_RESERVED_1,
		MEMORY_TYPE_RESERVED_2,
		MEMORY_TYPE_RESERVED_3,
		SPECIAL_MEMORY_LAYOUT,
		CAN_ACCESS_CORE2,
		MAX_KERNEL_FLAG = 23,
	};

	enum MemoryType
	{
		APPLICATION = 1,
		SYSTEM = 2,
		BASE = 3
	};

	struct sMemoryMapping
	{
		u32 start;
		u32 end;
		bool read_only;
	};

	Arm11KernelCaps();
	Arm11KernelCaps(const u8* data);
	Arm11KernelCaps(const Arm11KernelCaps& other);
	~Arm11KernelCaps();

	void operator=(const Arm11KernelCaps& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData();
	void SetInterruptACL(const std::vector<u8>& list);
	void SetSystemCallACL(const std::vector<u8>& list);
	void SetReleaseKernelVersion(u16 version);
	void SetHandleTableSize(u16 size);
	void SetMemoryType(MemoryType type);
	void SetKernelFlags(u32 flags);
	void HasKernelFlag(KernelFlag bit);
	void SetKernelFlags(const std::vector<KernelFlag>& flags);
	void SetStaticMapping(const std::vector<struct sMemoryMapping>& mapping_list);
	void SetIOMapping(const std::vector<struct sMemoryMapping>& mapping_list);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	const std::vector<u8>& GetInterruptACL() const;
	const std::vector<u8>& GetSystemCallACL() const;
	u16 GetReleaseKernelVersion() const;
	u16 GetHandleTableSize() const;
	MemoryType GetMemoryType() const;
	u32 GetKernelFlags() const;
	const std::vector<KernelFlag>& GetKernelFlagList() const;
	const std::vector<sMemoryMapping>& GetMemoryMapping() const;
	const std::vector<sMemoryMapping>& GetIORegisterMapping() const;


private:
	const std::string kModuleName = "ARM11_KERNEL_CAPS";
	static const int kKernelCapsNum = 28;

	static const int kMemoryTypeShift = 8;
	static const u8 kMemoryTypeMask = 0xf;
	static const u8 kMemoryMappingReadOnlyShift = 20;
	static const u8 kMemoryMappingPageShift = 12;

	static const u32 kMaxInteruptValue = BIT(7) - 1;
	static const u32 kMaxStoredInteruptNum = 32;
	static const u32 kMaxInteruptNum = 0x80;
	static const u32 kMaxSvcValue = 0x7D;
	static const u32 kMaxSvcNum = 0xC0;
	static const int kSyscallShift = 24;

	// Private Enums
	enum CapabilityPrefixBits
	{
		PREFIX_INTERRUPT = 3,
		PREFIX_SYSTEM_CALL = 4,
		PREFIX_RELEASE_KERNEL_VERSION = 6,
		PREFIX_HANDLE_TABLE_SIZE = 7,
		PREFIX_KERNEL_FLAG = 8,
		PREFIX_MAPPING_PAGE_RANGE = 9,
		PREFIX_MAPPING_PAGE = 11,
		PREFIX_UNUSED = 32,
	};

	inline u32 make_capability_prefix(u32 prefix_bits) { return ((u32)(-1)) << (32 - prefix_bits); }
	inline u32 make_capability_mask(u32 prefix_bits) { return ((u32)(-1)) >> (prefix_bits + 1); }
	inline u32 make_capability(u32 prefix_bits, u32 data) { return make_capability_prefix(prefix_bits) | (data & make_capability_mask(prefix_bits)); }
	inline u32 get_capability_data(u32 prefix_bits, u32 cap) { return cap & make_capability_mask(prefix_bits); }
	inline bool capability_has_prefix(u32 prefix_bits, u32 cap) { return ((cap & make_capability_prefix(prefix_bits)) == make_capability_prefix(prefix_bits)) && ((cap & ~make_capability_mask(prefix_bits)) == make_capability_prefix(prefix_bits)); }
	inline u32 get_capability_prefix(u32 cap)
	{
		u32 prefix = 0;
		while ((cap & BIT(31)) != 0)
		{
			cap <<= 1;
			prefix++;
		}
		return prefix;
	}

	inline u32 align_to_page(u32 address) { return (address & 0xFFF) ? (address & ~0xFFF) + 0x1000 : address; }
	inline u32 make_mapping_data(u32 address, bool read_only) { return (u32)(address >> kMemoryMappingPageShift) | (u32)(read_only << kMemoryMappingReadOnlyShift); }
	inline bool is_mapping_readonly(u32 data) { return (data >> kMemoryMappingReadOnlyShift) == true; }
	inline u32 get_mapping_address(u32 data) { return data << kMemoryMappingPageShift; }

	// Private Structures
#pragma pack (push, 1)
	struct sArm11KernelCaps
	{
	private:
		u32 kernel_caps_[kKernelCapsNum];
		u8 reserved[0x10];
	public:
		u32 kernel_capability(int index) const { return le_word(kernel_caps_[index]); }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_kernel_capability(int index, u32 desc) { kernel_caps_[index] = le_word(desc); }
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// variables
	std::vector<u8> interrupt_acl_;
	std::vector<u8> systemcall_acl_;
	u16 release_kernel_version_;
	u16 handle_table_size_;
	MemoryType memory_type_;
	u32 kernel_flag_;
	std::vector<KernelFlag> kernel_flag_list_;
	std::vector<sMemoryMapping> memory_mapping_;
	std::vector<sMemoryMapping> io_register_mapping_;

	void ClearDeserialisedVariables();
	void SerialiseInterrupts(std::vector<u32>& interupt_caps);
	void SerialiseSystemCalls(std::vector<u32>& system_call_caps);
	void SerialiseReleaseKernelVersion(u32& release_kernel_version);
	void SerialiseHandleTableSize(u32& handle_table_size);
	void SerialiseKernelFlags(u32& kernel_flags);
	void SerialiseMemoryMappings(std::vector<u32>& mappings);
	void SerialiseIoRegisterMappings(std::vector<u32>& mappings);
	void DeserialiseInterrupt(const std::vector<u32>& interupt_caps);
	void DeserialiseSystemCall(const std::vector<u32>& system_call_caps);
	void DeserialiseKernelFlag(u32 data);
	void DeserialisePageRangeMapping(u32 start, u32 end);
	void DeserialisePageMapping(u32 data);
};

