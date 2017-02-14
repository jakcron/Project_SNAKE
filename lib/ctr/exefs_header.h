#pragma once
#include <vector>
#include <fnd/types.h>
#include <fnd/memory_blob.h>
#include <crypto/crypto.h>



class ExefsHeader
{
public:
	// Public constants
	static const size_t kExefsFileNameLength = 8;
	static const size_t kExefsFileNum = 8;

	// Public structures
	struct sExefsFile
	{
		std::string name;
		u32 offset;
		u32 size;
		u8 hash[Crypto::kSha256HashLen];
	};

	// Constructor/Destructor
	ExefsHeader();
	ExefsHeader(const u8* data);
	ExefsHeader(const ExefsHeader& other);
	~ExefsHeader();

	void operator=(const ExefsHeader& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData();
	void SetAlignSize(u32 size);
	void AddExefsFile(const std::string& name, u32 size, u8 hash[Crypto::kSha256HashLen]);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	size_t GetExefsSize() const;
	const std::vector<sExefsFile>& GetExefsFiles() const;

private:
	const std::string kModuleName = "EXEFS_HEADER";
	static const size_t kDefaultAlignSize = 0x200;

	// Private Structures
#pragma pack (push, 1)
	struct sFileEntry
	{
	private:
		char name_[kExefsFileNameLength];
		u32 offset_;
		u32 size_;
	public:
		const char* name() const { return name_; }
		u32 offset() const { return le_word(offset_); }
		u32 size() const { return le_word(size_); }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_name(const char* name) { strncpy(name_, name, kExefsFileNameLength); }
		void set_offset(u32 offset) { offset_ = le_word(offset); }
		void set_size(u32 size) { size_ = le_word(size); }
	};

	struct sExefsHeader
	{
	private:
		sFileEntry files_[kExefsFileNum];
		u8 reserved[0x80];
		u8 file_hashes_[kExefsFileNum][Crypto::kSha256HashLen];
	public:
		const char* name(int index) const { return files_[index].name(); }
		u32 offset(int index) const { return files_[index].offset(); }
		u32 size(int index) const { return files_[index].size(); }
		const u8* hash(int index) const { return file_hashes_[kExefsFileNum - 1 - index]; }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_name(int index, const char* name) { files_[index].set_name(name); }
		void set_offset(int index, u32 offset) { files_[index].set_offset(offset); }
		void set_size(int index, u32 size) { files_[index].set_size(size); }
		void set_hash(int index, const u8* hash) { memcpy(file_hashes_[kExefsFileNum - 1 - index], hash, Crypto::kSha256HashLen); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	u32 align_size_;
	size_t exefs_size_;
	std::vector<sExefsFile> files_;

	void ClearDeserialisedVariables();
};

