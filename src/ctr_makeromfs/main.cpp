#include <fstream>
#include <ctr/romfs.h>
#include <ctr/ivfc.h>

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