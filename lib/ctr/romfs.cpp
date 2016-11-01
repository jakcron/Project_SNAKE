#include "romfs.h"
#include "romfs_dir_filter.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

// Apparently this is Nintendo's version of "Smallest prime >= the input"
static u32 CalcHashTableLen(u32 entryCount)
{
#define D(a) (count % (a) == 0)
	u32 count = entryCount;
	if (count < 3) count = 3;
	else if (count < 19) count |= 1;
	else while (D(2) || D(3) || D(5) || D(7) || D(11) || D(13) || D(17)) count++;
	return count;
#undef D
}

static u32 CalcHash(u32 parent, const utf16char_t *str, u32 total)
{
	u32 len = utf16_strlen(str);
	u32 hash = parent ^ 123456789;
	for (u32 i = 0; i < len; i++)
	{
		hash = (u32)((hash >> 5) | (hash << 27));
		hash ^= (u16)str[i];
	}
	return hash % total;
}

u32 CalcPathHash(u32 parent, const utf16char_t* path)
{
	u32 len = utf16_strlen(path);
	u32 hash = parent ^ 123456789;
	for (u32 i = 0; i < len; i++)
	{
		hash = (u32)((hash >> 5) | (hash << 27));//ror
		hash ^= (u16)path[i];
	}
	return hash;
}


Romfs::Romfs()
{
}

Romfs::~Romfs()
{
}

int Romfs::CreateRomfs(const char* dir)
{
	// scan root dir
	RomfsDirScanner scanner;
	safe_call(scanner.ScanDir(dir));

	
	// filter root dir
	RomfsDirFilter filter;
	filter.FilterFs(scanner.root_dir());
	
	// save copy of root dir
	root_ = filter.GetRootFs();

	// debug
	//scanner.PrintDirTree(root_, 1);

	// return if there's nothing in the directory
	if (GetDirNum(root_) == 0 && GetFileNum(root_) == 0)
		return 0;

	safe_call(CreateRomfsLayout());

	// add files and dirs to romfs layout
	AddDirToRomfs(root_, 0, kUnusedOffset);
	safe_call(AddDirChildToRomfs(root_, 0, 0));

	return 0;
}

u32 Romfs::GetDirNum(const RomfsDirScanner::sDirectory & dir)
{
	u32 num = dir.child.size();

	for (size_t i = 0; i < dir.child.size(); i++)
	{
		num += GetDirNum(dir.child[i]);
	}

	return num;
}

u32 Romfs::GetFileNum(const RomfsDirScanner::sDirectory & dir)
{
	u32 num = dir.file.size();
	for (size_t i = 0; i < dir.child.size(); i++)
	{
		num += GetFileNum(dir.child[i]);
	}

	return num;
}

u32 Romfs::GetDirTableSize(const RomfsDirScanner::sDirectory& dir)
{
	u32 size = sizeof(struct sDirectoryNode) + align(dir.namesize, 4);
	for (size_t i = 0; i < dir.child.size(); i++)
	{
		size += GetDirTableSize(dir.child[i]);
	}

	return size;
}

u32 Romfs::GetFileTableSize(const RomfsDirScanner::sDirectory& dir)
{
	u32 size = 0;
	for (size_t i = 0; i < dir.file.size(); i++)
	{
		size += sizeof(struct sFileNode) + align(dir.file[i].namesize, 4);
	}

	for (size_t i = 0; i < dir.child.size(); i++)
	{
		size += GetFileTableSize(dir.child[i]);
	}

	return size;
}

u64 Romfs::GetDataSize(const RomfsDirScanner::sDirectory& dir)
{
	u64 size = 0;
	for (size_t i = 0; i < dir.file.size(); i++)
	{
		size = align(size, 0x10) + dir.file[i].size;
	}

	for (size_t i = 0; i < dir.child.size(); i++)
	{
		size = align(size, 0x10) + GetDataSize(dir.child[i]);
	}

	return size;
}

int Romfs::CreateRomfsLayout()
{
	u32 dir_hash_table_size, dir_entry_table_size, file_hash_table_size, file_entry_table_size;
	u32 header_size;
	u64 data_size;

	// get sizes
	header_.dir_hash_num = CalcHashTableLen(GetDirNum(root_) + 1);
	header_.file_hash_num = CalcHashTableLen(GetFileNum(root_));

	dir_hash_table_size = (header_.dir_hash_num) * sizeof(u32);
	file_hash_table_size = (header_.file_hash_num) * sizeof(u32);
	dir_entry_table_size = GetDirTableSize(root_);
	file_entry_table_size = GetFileTableSize(root_);

	header_size = align(\
		sizeof(sRomfsHeader) \
		+ dir_hash_table_size + dir_entry_table_size \
		+ file_hash_table_size + file_entry_table_size \
		, 0x10);

	data_size = GetDataSize(root_);


	// allocate memory
	safe_call(data_.alloc(header_size + data_size));

	// set header
	sRomfsHeader* hdr = (sRomfsHeader*)data_.data();
	hdr->set_header_size(sizeof(sRomfsHeader));
	hdr->set_data_offset(header_size);

	u32 offset = sizeof(sRomfsHeader);
	for (size_t i = 0; i < kRomfsSectionNum; i++)
	{
		switch (i)
		{
		case(ROMFS_SECTION_DIR_HASH_TABLE) :
		{
			hdr->set_section(i, offset, dir_hash_table_size);
			header_.dir_hash_table = (u32*)(data_.data() + offset);
			break;
		}
		case(ROMFS_SECTION_DIR_ENTRY_TABLE) :
		{
			hdr->set_section(i, offset, dir_entry_table_size);
			header_.dir_entry_offset = 0;
			header_.dir_entry_table = (data_.data() + offset);
			break;
		}
		case(ROMFS_SECTION_FILE_HASH_TABLE) :
		{
			hdr->set_section(i, offset, file_hash_table_size);
			header_.file_hash_table = (u32*)(data_.data() + offset);
			break;
		}
		case(ROMFS_SECTION_FILE_ENTRY_TABLE) :
		{
			hdr->set_section(i, offset, file_entry_table_size);
			header_.file_entry_offset = 0;
			header_.file_entry_table = (data_.data() + offset);
			break;
		}
		}
		offset += hdr->section(i).size();
	}

	header_.data_offset = 0;
	header_.data = data_.data() + align(offset, 0x10);

	// set initial state for the hash tables
	for (u32 i = 0; i < header_.dir_hash_num; i++)
	{
		header_.dir_hash_table[i] = le_word(kUnusedOffset);
	}
	for (u32 i = 0; i < header_.file_hash_num; i++)
	{
		header_.file_hash_table[i] = le_word(kUnusedOffset);
	}


	return 0;
}

void Romfs::AddDirToRomfs(const RomfsDirScanner::sDirectory& dir, u32 parent, u32 sibling)
{
	struct sDirectoryNode* entry = (struct sDirectoryNode*)(header_.dir_entry_table + header_.dir_entry_offset);

	entry->set_parent_node(parent);
	entry->set_sibling_node(sibling);
	entry->set_child_node(kUnusedOffset);
	entry->set_file_node(kUnusedOffset);

	u32 hash = CalcHash(parent, dir.name, header_.dir_hash_num);
	entry->set_hash_sibling(header_.dir_hash_table[hash]);
	header_.dir_hash_table[hash] = le_word(header_.dir_entry_offset);

	entry->set_name(dir.name, dir.namesize);

	header_.dir_entry_offset += entry->node_size();
}

int Romfs::AddDirChildToRomfs(const RomfsDirScanner::sDirectory& dir, u32 parent, u32 diroff)
{
	struct sDirectoryNode* entry = (struct sDirectoryNode*)(header_.dir_entry_table + diroff);
	
	if (dir.file.size())
	{
		u32 sibling;
		entry->set_file_node(header_.file_entry_offset);
		for (size_t i = 0; i < dir.file.size(); i++)
		{
			sibling = (i == dir.file.size() - 1) ? kUnusedOffset : (header_.file_entry_offset + sizeof(struct sFileNode) + align(dir.file[i].namesize, 4));
			safe_call(AddFileToRomfs(dir.file[i], diroff, sibling));
		}
	}
	
	if (dir.child.size())
	{
		u32 sibling;
		std::vector<u32> child;
		entry->set_child_node(header_.dir_entry_offset);
		for (size_t i = 0; i < dir.child.size(); i++)
		{
			/* Store address for child */
			child.push_back(header_.dir_entry_offset);

			/* If is the last child directory, no more siblings  */
			sibling = (i == dir.child.size() - 1) ? kUnusedOffset : (header_.dir_entry_offset + sizeof(struct sDirectoryNode) + align(dir.child[i].namesize, 4));
		
			/* Create child directory entry */
			AddDirToRomfs(dir.child[i], diroff, sibling);
		}

		/* Populate child's childs */
		for (size_t i = 0; i < dir.child.size(); i++)
		{
			safe_call(AddDirChildToRomfs(dir.child[i], diroff, child[i]));
		}
	}

	return 0;
}

int Romfs::AddFileToRomfs(const RomfsDirScanner::sFile& file, u32 parent, u32 sibling)
{
	struct sFileNode* entry = (struct sFileNode*)(header_.file_entry_table + header_.file_entry_offset);
	
	entry->set_parent_node(parent);
	entry->set_sibling_node(sibling);
	entry->set_data_offset(0);
	entry->set_data_size(file.size);
	


	u32 hash = CalcHash(parent, file.name, header_.file_hash_num);
	entry->set_hash_sibling(header_.file_hash_table[hash]);
	header_.file_hash_table[hash] = le_word(header_.file_entry_offset);

	entry->set_name(file.name, file.namesize);
	
	if (file.size)
	{
		FILE *fp = os_fopen(file.path, OS_MODE_READ);
		if (!fp)
		{
			fprintf(stderr, "[ERROR] Failed to open file for romfs: ");
			os_fputs(file.path, stderr);
			fputs("\n", stderr);
			return 1;
		}

		// align data pos to 0x10 bytes
		header_.data_offset = align(header_.data_offset, 0x10);
		entry->set_data_offset(header_.data_offset);

		fread(header_.data + header_.data_offset, 1, file.size, fp);
		fclose(fp);
	}

	header_.data_offset += file.size;
	header_.file_entry_offset += entry->node_size();

	return 0;
}