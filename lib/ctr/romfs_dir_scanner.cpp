#include <cstdlib>
#include "romfs_dir_scanner.h"

#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

RomfsDirScanner::RomfsDirScanner()
{
	InitDirectory(root_);
}

RomfsDirScanner::~RomfsDirScanner()
{
	FreeDirectory(root_);
}

int RomfsDirScanner::ScanDir(const char* root)
{
	static const utf16char_t EMPTY_PATH[1] = { '\0' };
	root_.path = os_CopyConvertCharStr(root);
	root_.name = utf16_CopyStr(EMPTY_PATH);
	root_.namesize = 0;

	return PopulateDir(root_);
}

void RomfsDirScanner::InitDirectory(struct RomfsDirScanner::sDirectory& dir)
{
	dir.path = NULL;
	dir.name = NULL;
	dir.namesize = 0;
	dir.child.clear();
	dir.file.clear();
}

void RomfsDirScanner::FreeDirectory(struct RomfsDirScanner::sDirectory& dir)
{
	// free memory allocations
	if (dir.path)
	{
		free(dir.path);
	}
	if (dir.name)
	{
		free(dir.name);
	}

	// free child dirs
	for (size_t i = 0; i < dir.child.size(); i++)
	{
		FreeDirectory(dir.child[i]);
	}

	// free files
	for (size_t i = 0; i < dir.file.size(); i++)
	{
		if (dir.file[i].path)
		{
			free(dir.file[i].path);
		}

		if (dir.file[i].name)
		{
			free(dir.file[i].name);
		}

		dir.file[i].path = NULL;
		dir.file[i].name = NULL;
		dir.file[i].namesize = 0;
		dir.file[i].size = 0;
	}

	// clear this directory
	InitDirectory(dir);
}

int RomfsDirScanner::PopulateDir(struct RomfsDirScanner::sDirectory& dir)
{
	_OSDIR *dp;
	struct _osstat st;
	struct _osdirent *entry;

	// Open Directory
	if ((dp = os_opendir(dir.path)) == NULL)
	{
		printf("[ERROR] Failed to open directory: \"");
		os_fputs(dir.path, stdout);
		printf("\"\n");
		return 1;
	}

	// Process Entries
	while ((entry = os_readdir(dp)) != NULL)
	{
		// Skip hidden files and directories (starting with ".")
		if (entry->d_name[0] == (oschar_t)'.')
			continue;

		// Get native FS path
		oschar_t *path = os_AppendToPath(dir.path, entry->d_name);

		// Opening directory with fs path to test if directory
		if (os_stat(path, &st) == 0 && S_IFDIR&st.st_mode) {
			struct sDirectory child;
			child.path = path;
			child.name = utf16_CopyConvertOsStr(entry->d_name);
			child.namesize = utf16_strlen(child.name)*sizeof(utf16char_t);

			// populate child
			PopulateDir(child);

			// add to parent struct
			dir.child.push_back(child);
		}
		// Otherwise this is a file
		else {
			struct sFile file;
			file.path = path;
			file.name = utf16_CopyConvertOsStr(entry->d_name);
			file.namesize = utf16_strlen(file.name)*sizeof(utf16char_t);
			file.size = os_fsize(path);
			dir.file.push_back(file);
		}
	}

	os_closedir(dp);

	return 0;
}