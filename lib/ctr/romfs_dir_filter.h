#pragma once
#include "romfs_dir_scanner.h"

class RomfsDirFilter
{
public:
	RomfsDirFilter();
	~RomfsDirFilter();

	void FilterFs(const RomfsDirScanner::sDirectory& src);

	const RomfsDirScanner::sDirectory& GetRootFs();
private:
	RomfsDirScanner::sDirectory root_;

	u32 GetNestedDirNum(const RomfsDirScanner::sDirectory& parent);
	u32 GetNestedFileNum(const RomfsDirScanner::sDirectory& parent);

	void CopyDirNode(const RomfsDirScanner::sDirectory& src, RomfsDirScanner::sDirectory& dst);
	void CopyFileNode(const RomfsDirScanner::sFile& src, RomfsDirScanner::sFile& dst);

};

