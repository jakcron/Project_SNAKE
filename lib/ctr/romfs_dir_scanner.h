#pragma once
#include <vector>
#include "oschar.h"
#include "types.h"

class RomfsDirScanner
{
public:
	struct sFile
	{
		oschar_t* path;
		utf16char_t* name;
		u32 namesize;
		u64 size;
	};

	struct sDirectory
	{
		oschar_t* path;
		utf16char_t* name;
		u32 namesize;

		std::vector<struct sDirectory> child;
		std::vector<struct sFile> file;
	};

	RomfsDirScanner();
	~RomfsDirScanner();

	int ScanDir(const char* root);

	inline struct sDirectory const& root_dir() const { return root_; }

private:
	struct sDirectory root_;

	void InitDirectory(struct sDirectory& dir);
	void FreeDirectory(struct sDirectory& dir);
	int PopulateDir(struct sDirectory& dir);
};