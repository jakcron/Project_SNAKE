#pragma once
#include <fnd/types.h>
#include <fnd/ByteBuffer.h>
#include <ctr/romfs_dir_scanner.h>

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
	struct sSectionGeometry
	{
	private:
		u32 offset_;
		u32 size_;
	public:
		u32 offset() const { return le_word(offset_); }
		u32 size() const { return le_word(size_); }

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
	
		void set_header_size(u32 size) { header_size_ = le_word(size); }
		void set_section(int index, u32 offset, u32 size) { section_[index].set_offset(offset); section_[index].set_size(size); };
		void set_data_offset(u32 offset) { data_offset_ = le_word(offset); }
	};

	struct sDirectoryNode
	{
	private:
		u32 parent_offset_;
		u32 sibling_offset_;
		u32 child_offset_;
		u32 file_offset_;
		u32 hash_offset_;
		u32 name_size_;
	public:
		u32 parent_node() const { return le_word(parent_offset_); }
		u32 sibling_node() const { return le_word(sibling_offset_); }
		u32 child_node() const { return le_word(child_offset_); }
		u32 file_node() const { return le_word(file_offset_); }
		u32 hash_sibling_node() const { return le_word(hash_offset_); }
		u32 name_size() const { return le_word(name_size_); }
		u32 node_size() const { return align(sizeof(sDirectoryNode) + name_size(), 4); }
		const utf16char_t* name_str() const { return (const utf16char_t*)(((u8*)this) + sizeof(sDirectoryNode)); }

		void set_parent_node(u32 node) { parent_offset_ = le_word(node); }
		void set_sibling_node(u32 node) { sibling_offset_ = le_word(node); }
		void set_child_node(u32 node) { child_offset_ = le_word(node); }
		void set_file_node(u32 node) { file_offset_ = le_word(node); }
		void set_hash_sibling(u32 node) { hash_offset_ = le_word(node); }
		void set_name(const utf16char_t* name, u32 raw_size)
		{
			utf16char_t* name_ = (utf16char_t*)(((u8*)this) + sizeof(sDirectoryNode));
			name_size_ = le_word(raw_size);
			for (u32 i = 0; i < raw_size / sizeof(utf16char_t); i++)
			{
				name_[i] = le_hword(name[i]);
			}
		}
	};

	struct sFileNode
	{
	private:
		u32 parent_offset_;
		u32 sibling_offset_;
		u64 data_offset_;
		u64 data_size_;
		u32 hash_offset_;
		u32 name_size_;
	public:
		u32 parent_node() const { return le_word(parent_offset_); }
		u32 sibling_node() const { return le_word(sibling_offset_); }
		u32 data_offset() const { return le_dword(data_offset_); }
		u32 data_size() const { return le_dword(data_size_); }
		u32 hash_sibling_node() const { return le_word(hash_offset_); }
		u32 name_size() const { return le_word(name_size_); }
		u32 node_size() const { return align(sizeof(sFileNode) + name_size(), 4); }
		const utf16char_t* name_str() const { return (const utf16char_t*)(((u8*)this) + sizeof(sFileNode)); }

		void set_parent_node(u32 node) { parent_offset_ = le_word(node); }
		void set_sibling_node(u32 node) { sibling_offset_ = le_word(node); }
		void set_data_offset(u64 offset) { data_offset_ = le_dword(offset); }
		void set_data_size(u64 size) { data_size_ = le_dword(size); }
		void set_hash_sibling(u32 node) { hash_offset_ = le_word(node); }
		void set_name(const utf16char_t* name, u32 raw_size)
		{
			utf16char_t* name_ = (utf16char_t*)(((u8*)this) + sizeof(sFileNode));
			name_size_ = le_word(raw_size);
			for (u32 i = 0; i < raw_size / sizeof(utf16char_t); i++)
			{
				name_[i] = le_hword(name[i]);
			}
		}
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
	
	//RomfsDirScanner scanner_;
	RomfsDirScanner::sDirectory root_;
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