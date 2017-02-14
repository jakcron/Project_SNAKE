#pragma once
#include <vector>
#include <fnd/types.h>
#include <fnd/memory_blob.h>

class Arm9AccessControl
{
public:
	// Public enums
	enum IORight
	{
		FS_MOUNT_NAND,
		FS_MOUNT_NAND_RO_WRITE,
		FS_MOUNT_TWLN,
		FS_MOUNT_WNAND,
		FS_MOUNT_CARD_SPI,
		USE_SDIF3,
		CREATE_SEED,
		USE_CARD_SPI,
		SD_APPLICATION,
		USE_DIRECT_SDMC,
	};

	// Constructor/Destructor
	Arm9AccessControl();
	Arm9AccessControl(const u8* data);
	Arm9AccessControl(const Arm9AccessControl& other);
	~Arm9AccessControl();

	void operator=(const Arm9AccessControl& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData();
	void SetIORights(const std::vector<IORight>& rights);
	void SetDescVersion(u8 version);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	const std::vector<IORight>& GetIORights() const;
	u8 GetDescVersion() const;

private:
	const std::string kModuleName = "ARM9_ACCESS_CONTROL";
	static const int kMaxIOFlags = 120;

	// Private Structures
#pragma pack (push, 1)
	struct sArm9AccessControl
	{
	private:
		u8 io_rights_[0xf];
		u8 desc_version_;
	public:
		bool has_io_right(IORight index) const { return (io_rights_[index/8] & BIT(index%8)) != 0; }
		u8 desc_version() const { return desc_version_; }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_io_right(IORight index, bool enabled) { io_rights_[index / 8] &= ~BIT(index % 8);  io_rights_[index / 8] |= (enabled << (index % 8)); }
		void set_desc_version(u8 version) { desc_version_ = version; }
	};

#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	std::vector<IORight> io_rights_;
	u8 desc_version_;

	void ClearDeserialisedVariables();
};

