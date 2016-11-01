#include "romfs.h"
#include "ivfc.h"
#include "ByteBuffer.h"
#include <fstream>

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		printf("CTR MAKE-ROMFS\n");
		printf("usage: %s <romfs dir> <romfs bin>\n", argv[0]);
		return 1;
	}
	// create romfs
	Romfs romfs;
	romfs.CreateRomfs(argv[1]);

	Ivfc ivfc;
	ivfc.CreateIvfcHashTree(romfs.data_blob(), romfs.data_size());


	/*
	fseek(fp, header_.romfs_offset(), SEEK_SET);
	fwrite(ivfc_.header_blob(), 1, ivfc_.header_size(), fp);

	// write level2 a.k.a. romfs
	for (u32 i = 0; i < romfs_.data_size() / Ivfc::kBlockSize; i++)
	{
		fwrite(romfs_.data_blob() + i*Ivfc::kBlockSize, 1, Ivfc::kBlockSize, fp);
	}
	if (romfs_.data_size() % Ivfc::kBlockSize)
	{
		u8 block[Ivfc::kBlockSize] = { 0 };
		memcpy(block, romfs_.data_blob() + (romfs_.data_size() / Ivfc::kBlockSize)*Ivfc::kBlockSize, romfs_.data_size() % Ivfc::kBlockSize);
		fwrite(block, 1, Ivfc::kBlockSize, fp);
	}

	fwrite(ivfc_.level0_blob(), 1, ivfc_.level0_size(), fp);
	fwrite(ivfc_.level1_blob(), 1, ivfc_.level1_size(), fp);
	*/

	// write to file
	std::ofstream outfile(argv[2], std::ofstream::binary);

	// header
	outfile.write((const char*)ivfc.header_blob(), ivfc.header_size());

	// level2 aka actual ROMFS
	for (u32 i = 0; i < romfs.data_size() / Ivfc::kBlockSize; i++)
	{
		outfile.write((const char*)romfs.data_blob() + i*Ivfc::kBlockSize, Ivfc::kBlockSize);
	}
	if (romfs.data_size() % Ivfc::kBlockSize)
	{
		u8 block[Ivfc::kBlockSize] = { 0 };
		memcpy(block, romfs.data_blob() + (romfs.data_size() / Ivfc::kBlockSize)*Ivfc::kBlockSize, romfs.data_size() % Ivfc::kBlockSize);
		outfile.write((const char*)block, Ivfc::kBlockSize);
	}

	// level0 & level1
	outfile.write((const char*)ivfc.level0_blob(), ivfc.level0_size());
	outfile.write((const char*)ivfc.level1_blob(), ivfc.level1_size());

	return 0;
}