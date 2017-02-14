#pragma once
#include <cmath>
#include <fnd/types.h>
#include <fnd/memory_blob.h>
#include <crypto/crypto.h>

class IvfcHeader
{
public:
	// Public enums/constants
	enum IvfcType
	{
		IVFC_ROMFS = BIT(16),
		IVFC_EXTDATA = BIT(17),
	};
	static const size_t kLevelNum = 3;

	// Constructor/Destructor
	IvfcHeader();
	IvfcHeader(const u8* data);
	IvfcHeader(const IvfcHeader& other);
	~IvfcHeader();

	void operator=(const IvfcHeader& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData(u64 level_2_size, IvfcType type);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	IvfcType GetType() const;
	u32 GetMasterHashSize() const;
	u32 GetOptionalSize() const;
	u64 GetLevelOffset(size_t index) const;
	u64 GetLevelSize(size_t index) const;
	u64 GetLevelBlockSize(size_t index) const;
	u64 GetLevelAlignedSize(size_t index) const;


private:
	const std::string kModuleName = "IVFC_HEADER";
	const char kIvfcStructSignature[4] = { 'I', 'V', 'F', 'C' };
	static const size_t kDefaultRomfsBlockSize = 0x1000;
	static const size_t kDefaultExtdataBlockSize = 0x200;

#pragma pack (push, 1)
	struct sIvfcLevel
	{
	private:
		u64 offset_;
		u64 size_;
		u32 block_size_;
		u8 reserved[4];
	public:
		u64 offset() const { return le_dword(offset_); }
		u64 size() const { return le_dword(size_); }
		u64 block_size() const { return (u64)1 << (u64)le_word(block_size_); }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_offset(u64 offset) { offset_ = le_dword(offset); }
		void set_size(u64 size) { size_ = le_dword(size); }
		void set_block_size(u64 block_size) { block_size_ = le_word(log2l(block_size)); }
	};

	struct sIvfcHeader
	{
	private:
		char struct_signature_[4];
		u32 type_;
		u32 master_hash_size_;
		sIvfcLevel level_[kLevelNum];
		u32 optional_size_;
		u8 reserved[4];
	public:
		const char* struct_signature() const { return struct_signature_; }
		IvfcType type() const { return (IvfcType)le_word(type_); }
		u32 master_hash_size() const { return le_word(master_hash_size_); }
		const sIvfcLevel& level(size_t index) const { return level_[index]; }
		u32 optional_size() const { return le_word(optional_size_); }
		
		void clear() { memset(this, 0, sizeof(*this)); }

		void set_struct_signature(const char* sig) { strncpy(struct_signature_, sig, 4); }
		void set_type(IvfcType type) { type_ = le_word(type); }
		void set_master_hash_size(u32 size) { master_hash_size_ = le_word(size); }
		void set_level(size_t index, u64 offset, u64 size, u64 block_size) { level_[index].set_offset(offset); level_[index].set_size(size); level_[index].set_block_size(block_size); }
		void set_optional_size(u32 size) { optional_size_ = le_word(size); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	IvfcType type_;
	u32 master_hash_size_;
	u32 optional_size_;
	sIvfcLevel level_[kLevelNum];

	void ValidateIvfcType(IvfcType type);
	u64 GetDefaultBlockSize(IvfcType type);
	u64 CalculateHashNum(u64 size, u64 block_size);

	void ClearDeserialisedVariables();
};

