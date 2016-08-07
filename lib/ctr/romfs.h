#pragma once
#include "types.h"
#include "ByteBuffer.h"
#include "romfs_dir_scanner.h"

class Romfs
{
public:
	Romfs();
	~Romfs();

	// creating romfs from directory path
	int CreateRomfs(const char* dir);
	
	inline const u8* data_blob() const { return data_.data_const(); }
	inline u64 data_size() const { return data_.size(); }
private:
	static const int kRomfsSectionNum = 4;
	static const u32 kUnusedOffset = 0xffffffff;

	enum RomfsHeaderSections
	{
		ROMFS_SECTION_DIR_HASH_TABLE,
		ROMFS_SECTION_DIR_ENTRY_TABLE,
		ROMFS_SECTION_FILE_HASH_TABLE,
		ROMFS_SECTION_FILE_ENTRY_TABLE
	};

#pragma pack (push, 1)
	struct sRomfsHeader
	{
		u32 header_size;
		struct sRomfsSectionGeometry
		{
			u32 offset;
			u32 size;
		} section[kRomfsSectionNum];
		u32 data_offset;
	};

	struct sRomfsDirEntry
	{
		u32 parent_offset;
		u32 sibling_offset;
		u32 child_offset;
		u32 file_offset;
		u32 hash_offset;
		u32 name_size;
	};

	struct sRomfsFileEntry
	{
		u32 parent_offset;
		u32 sibling_offset;
		u64 data_offset;
		u64 data_size;
		u32 hash_offset;
		u32 name_size;
	};
#pragma pack (pop)

	struct sRomfsHeaderPointers {
		u32 dir_hash_num;
		u32* dir_hash_table;	

		u32 file_hash_num;
		u32* file_hash_table;

		u32 dir_entry_offset;
		u8* dir_entry_table;

		u32 file_entry_offset;
		u8* file_entry_table;

		u64 data_offset;
		u8* data;
	} header_;
	
	RomfsDirScanner scanner_;
	ByteBuffer data_; // raw romfs filesystem

	u32 GetDirNum(const struct RomfsDirScanner::sDirectory& dir);
	u32 GetFileNum(const struct RomfsDirScanner::sDirectory& dir);
	u32 GetDirTableSize(const struct RomfsDirScanner::sDirectory& dir);
	u32 GetFileTableSize(const struct RomfsDirScanner::sDirectory& dir);
	u64 GetDataSize(const struct RomfsDirScanner::sDirectory& dir);

	int CreateRomfsLayout();

	void AddDirToRomfs(const struct RomfsDirScanner::sDirectory& dir, u32 parent, u32 sibling);
	int AddDirChildToRomfs(const struct RomfsDirScanner::sDirectory& dir, u32 parent, u32 diroff);
	int AddFileToRomfs(const RomfsDirScanner::sFile& file, u32 parent, u32 sibling);
};