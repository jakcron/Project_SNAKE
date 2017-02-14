#pragma once
#include <fnd/types.h>
#include <fnd/memory_blob.h>
#include <crypto/crypto.h>

class RomfsHeader
{
private: /* private definition of header */
	static const size_t kRomfsSectionNum = 4;

#pragma pack (push, 1)
	struct sSectionGeometry
	{
	private:
		u32 offset_;
		u32 size_;
	public:
		u32 offset() const { return le_word(offset_); }
		u32 size() const { return le_word(size_); }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_offset(u32 offset) { offset_ = le_word(offset); }
		void set_size(u32 size) { size_ = le_word(size); }
	};

	struct sRomfsHeader
	{
	private:
		u32 header_size_;
		sSectionGeometry section_[kRomfsSectionNum];
		u32 data_offset_;
	public:
		u32 header_size() const { return le_word(header_size_); }
		const sSectionGeometry& section(int index) const { return section_[index]; }
		u32 data_offset() const { return le_word(data_offset_); };

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_header_size(u32 size) { header_size_ = le_word(size); }
		void set_section(int index, u32 offset, u32 size) { section_[index].set_offset(offset); section_[index].set_size(size); };
		void set_data_offset(u32 offset) { data_offset_ = le_word(offset); }
	};
#pragma pack (pop)
	
public: /* public API */
	static const size_t kSize = sizeof(sRomfsHeader);

	RomfsHeader();
	RomfsHeader(const u8* data);
	~RomfsHeader();

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData();
	void SetDirInfo(u32 node_table_size, u32 hashmap_table_size);
	void SetFileInfo(u32 node_table_size, u32 hashmap_table_size);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	u32 GetDirHashMapTableOffset() const;
	u32 GetDirHashMapTableSize() const;
	u32 GetDirNodeTableOffset() const;
	u32 GetDirNodeTableSize() const;
	u32 GetFileHashMapTableOffset() const;
	u32 GetFileHashMapTableSize() const;
	u32 GetFileNodeTableOffset() const;
	u32 GetFileNodeTableSize() const;
	u32 GetDataOffset() const;

private: /* private members */
	const std::string kModuleName = "ROMFS_HEADER";
	enum RomfsHeaderSections
	{
		DIR_HASHMAP_TABLE,
		DIR_NODE_TABLE,
		FILE_HASHMAP_TABLE,
		FILE_NODE_TABLE
	};

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	sSectionGeometry sections_[kRomfsSectionNum];
	u32 data_offset_;

	void ClearDeserialisedVariables();
};

