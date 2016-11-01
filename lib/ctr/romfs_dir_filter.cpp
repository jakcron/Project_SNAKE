#include "romfs_dir_filter.h"



RomfsDirFilter::RomfsDirFilter()
{
}


RomfsDirFilter::~RomfsDirFilter()
{
}

void RomfsDirFilter::FilterFs(const RomfsDirScanner::sDirectory & src)
{
	CopyDirNode(src, root_);
}

const RomfsDirScanner::sDirectory & RomfsDirFilter::GetRootFs()
{
	return root_;
}

u32 RomfsDirFilter::GetNestedDirNum(const RomfsDirScanner::sDirectory & parent)
{
	u32 num = parent.child.size();
	for (auto dir : parent.child)
	{
		num += GetNestedDirNum(dir);
	}
	return num;
}

u32 RomfsDirFilter::GetNestedFileNum(const RomfsDirScanner::sDirectory & parent)
{
	u32 num = 0 + parent.file.size();
	for (auto dir : parent.child)
	{
		num += GetNestedFileNum(dir);
	}
	return num;
}

void RomfsDirFilter::CopyDirNode(const RomfsDirScanner::sDirectory & src, RomfsDirScanner::sDirectory & dst)
{
	dst.path = os_CopyStr(src.path);
	dst.name = utf16_CopyStr(src.name);
	dst.namesize = src.namesize;
	for (auto file : src.file)
	{
		dst.file.push_back(file);
	}

	for (auto dir : src.child)
	{
		/*
		if(GetNestedFileNum(dir))
		{ 
			printf("this was included: ");
			os_fputs(dir.path, stdout);
			printf("\n");
			RomfsDirScanner::sDirectory dir_new;
			CopyDirNode(dir, dir_new);
			dst.child.push_back(dir_new);
		}
		else
		{
			printf("this was ignored: ");
			os_fputs(dir.path, stdout);
			printf("\n");
		}
		*/
		if (GetNestedFileNum(dir) > 0)
		{
			RomfsDirScanner::sDirectory dir_new;
			CopyDirNode(dir, dir_new);
			dst.child.push_back(dir_new);
		}
	}
}

void RomfsDirFilter::CopyFileNode(const RomfsDirScanner::sFile & src, RomfsDirScanner::sFile & dst)
{
	dst.name = utf16_CopyStr(src.name);
	dst.namesize = src.namesize;
	dst.path = os_CopyStr(src.path);
	dst.size = src.size;
}
