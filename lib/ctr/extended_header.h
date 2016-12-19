#pragma once
#include <fnd/types.h>
#include <ctr/system_control_info.h>
#include <ctr/arm11_local_caps.h>
#include <ctr/arm11_kernel_caps.h>
#include <ctr/arm9_access_control.h>

class ExtendedHeader
{
public:
	// Constructor/Destructor
	ExtendedHeader();
	ExtendedHeader(const u8* data);
	ExtendedHeader(const ExtendedHeader& other);
	ExtendedHeader(const SystemControlInfo& system, const Arm11LocalCaps& arm11_local, const Arm11KernelCaps& arm11_kernel, const Arm9AccessControl& arm9);
	~ExtendedHeader();

	void operator=(const ExtendedHeader& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData();
	void SetSystemControlInfo(const SystemControlInfo& system);
	void SetArm11LocalCaps(const Arm11LocalCaps& arm11_local);
	void SetArm11KernelCaps(const Arm11KernelCaps& arm11_kernel);
	void SetArm9AccessControl(const Arm9AccessControl& arm9);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	const SystemControlInfo& GetSystemControlInfo() const;
	const Arm11LocalCaps& GetArm11LocalCaps() const;
	const Arm11KernelCaps& GetArm11KernelCaps() const;
	const Arm9AccessControl& GetArm9AccessControl() const;

private:
	const std::string kModuleName = "EXTENDED_HEADER";
	static const size_t kSystemControlInfoSize = 0x200;
	static const size_t kArm11LocalCapsSize = 0x170;
	static const size_t kArm11KernelCapsSize = 0x80;
	static const size_t kArm9AccessControlSize = 0x10;

	// Private Structures
#pragma pack (push, 1)
	struct sExtendedHeader
	{
		u8 system_control_info[kSystemControlInfoSize];
		u8 arm11_local_caps[kArm11LocalCapsSize];
		u8 arm11_kernel_caps[kArm11KernelCapsSize];
		u8 arm9_access_control[kArm9AccessControlSize];
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// variables
	SystemControlInfo system_control_info_;
	Arm11LocalCaps arm11_local_caps_;
	Arm11KernelCaps arm11_kernel_caps_;
	Arm9AccessControl arm9_access_control_;
};

