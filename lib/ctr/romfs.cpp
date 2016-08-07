#include "romfs.h"

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
	safe_call(scanner_.ScanDir(dir));

	// return if there's nothing in the directory
	if (GetDirNum(scanner_.root_dir()) == 0 && GetFileNum(scanner_.root_dir()) == 0)
		return 0;

	safe_call(CreateRomfsLayout());

	// add files and dirs to romfs layout
	AddDirToRomfs(scanner_.root_dir(), 0, kUnusedOffset);
	safe_call(AddDirChildToRomfs(scanner_.root_dir(), 0, 0));

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
	u32 size = sizeof(struct sRomfsDirEntry) + align(dir.namesize, 4);
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
		size += sizeof(struct sRomfsFileEntry) + align(dir.file[i].namesize, 4);
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
	header_.dir_hash_num = CalcHashTableLen(GetDirNum(scanner_.root_dir()) + 1);
	header_.file_hash_num = CalcHashTableLen(GetFileNum(scanner_.root_dir()));

	dir_hash_table_size = (header_.dir_hash_num) * sizeof(u32);
	file_hash_table_size = (header_.file_hash_num) * sizeof(u32);
	dir_entry_table_size = GetDirTableSize(scanner_.root_dir());
	file_entry_table_size = GetFileTableSize(scanner_.root_dir());

	header_size = align(\
		sizeof(struct sRomfsHeader) \
		+ dir_hash_table_size + dir_entry_table_size \
		+ file_hash_table_size + file_entry_table_size \
		, 0x10);

	data_size = GetDataSize(scanner_.root_dir());


	// allocate memory
	safe_call(data_.alloc(header_size + data_size));

	// set header
	struct sRomfsHeader* hdr = (struct sRomfsHeader*)data_.data();
	hdr->header_size = le_word(sizeof(struct sRomfsHeader));
	hdr->data_offset = le_word(header_size);

	u32 offset = sizeof(struct sRomfsHeader);
	for (size_t i = 0; i < kRomfsSectionNum; i++)
	{
		switch (i)
		{
		case(ROMFS_SECTION_DIR_HASH_TABLE) :
		{
			hdr->section[i].size = le_word(dir_hash_table_size);
			header_.dir_hash_table = (u32*)(data_.data() + offset);
			break;
		}
		case(ROMFS_SECTION_DIR_ENTRY_TABLE) :
		{
			hdr->section[i].size = le_word(dir_entry_table_size);
			header_.dir_entry_offset = 0;
			header_.dir_entry_table = (data_.data() + offset);
			break;
		}
		case(ROMFS_SECTION_FILE_HASH_TABLE) :
		{
			hdr->section[i].size = le_word(file_hash_table_size);
			header_.file_hash_table = (u32*)(data_.data() + offset);
			break;
		}
		case(ROMFS_SECTION_FILE_ENTRY_TABLE) :
		{
			hdr->section[i].size = le_word(file_entry_table_size);
			header_.file_entry_offset = 0;
			header_.file_entry_table = (data_.data() + offset);
			break;
		}
		}
		hdr->section[i].offset = le_word(offset);
		offset += le_word(hdr->section[i].size);
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
	struct sRomfsDirEntry* entry = (struct sRomfsDirEntry*)(header_.dir_entry_table + header_.dir_entry_offset);
	utf16char_t* name = (utf16char_t*)(header_.dir_entry_table + header_.dir_entry_offset + sizeof(struct sRomfsDirEntry));

	entry->parent_offset = le_word(parent);
	entry->sibling_offset = le_word(sibling);
	entry->child_offset = le_word(kUnusedOffset);
	entry->file_offset = le_word(kUnusedOffset);

	u32 hash = CalcHash(parent, dir.name, header_.dir_hash_num);
	entry->hash_offset = header_.dir_hash_table[hash];
	header_.dir_hash_table[hash] = le_word(header_.dir_entry_offset);

	entry->name_size = le_dword(dir.namesize);
	for (u32 i = 0; i < dir.namesize / sizeof(utf16char_t); i++)
	{
		name[i] = le_hword(dir.name[i]);
	}

	header_.dir_entry_offset += (sizeof(struct sRomfsDirEntry) + align(dir.namesize, 4));
}

int Romfs::AddDirChildToRomfs(const RomfsDirScanner::sDirectory& dir, u32 parent, u32 diroff)
{
	struct sRomfsDirEntry* entry = (struct sRomfsDirEntry*)(header_.dir_entry_table + diroff);
	
	if (dir.file.size())
	{
		u32 sibling;
		entry->file_offset = le_word(header_.file_entry_offset);
		for (size_t i = 0; i < dir.file.size(); i++)
		{
			sibling = (i == dir.file.size() - 1) ? kUnusedOffset : (header_.file_entry_offset + sizeof(struct sRomfsFileEntry) + align(dir.file[i].namesize, 4));
			safe_call(AddFileToRomfs(dir.file[i], diroff, sibling));
		}
	}
	
	if (dir.child.size())
	{
		u32 sibling;
		std::vector<u32> child;
		entry->child_offset = le_word(header_.dir_entry_offset);
		for (size_t i = 0; i < dir.child.size(); i++)
		{
			/* Store address for child */
			child.push_back(header_.dir_entry_offset);

			/* If is the last child directory, no more siblings  */
			sibling = (i == dir.file.size() - 1) ? kUnusedOffset : (header_.dir_entry_offset + sizeof(struct sRomfsDirEntry) + align(dir.child[i].namesize, 4));
		
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
	struct sRomfsFileEntry* entry = (struct sRomfsFileEntry*)(header_.file_entry_table + header_.file_entry_offset);
	utf16char_t* name = (utf16char_t*)(header_.file_entry_table + header_.file_entry_offset + sizeof(struct sRomfsFileEntry));

	entry->parent_offset = le_word(parent);
	entry->sibling_offset = le_word(sibling);
	entry->data_offset = le_dword(0);
	entry->data_size = le_dword(file.size);

	u32 hash = CalcHash(parent, file.name, header_.file_hash_num);
	entry->hash_offset = header_.file_hash_table[hash];
	header_.file_hash_table[hash] = le_word(header_.file_entry_offset);

	entry->name_size = le_dword(file.namesize);
	for (u32 i = 0; i < file.namesize / sizeof(utf16char_t); i++)
	{
		name[i] = le_hword(file.name[i]);
	}
	
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
		entry->data_offset = le_dword(header_.data_offset);

		fread(header_.data + header_.data_offset, 1, file.size, fp);
		fclose(fp);
	}

	header_.data_offset += file.size;
	header_.file_entry_offset += (sizeof(struct sRomfsFileEntry) + align(file.namesize, 4));

	return 0;
}