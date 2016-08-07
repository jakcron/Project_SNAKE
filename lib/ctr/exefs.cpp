#include <cstdlib>
#include <cstdio>
#include <cstring>
#include "exefs.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

Exefs::Exefs() :
	block_size_(kDefaultBlockSize),
	file_(0)
{

}

Exefs::~Exefs()
{
}

int Exefs::CreateExefs()
{
	struct sExefsHeader* header;
	u32 offset;
	u32 size;

	size = sizeof(struct sExefsHeader);
	for (u32 i = 0; i < file_.size(); i++)
	{
		size += align(file_[i].size, block_size_);
	}

	safe_call(data_.alloc(size));

	header = (struct sExefsHeader*)data_.data();
	offset = 0;

	for (u32 i = 0; i < file_.size(); i++)
	{
		// copy data to header
		strncpy(header->files[i].name, file_[i].name, kMaxExefsFileNameLen);
		header->files[i].offset = le_word(offset);
		header->files[i].size = le_word(file_[i].size);
		memcpy(header->fileHashes[7 - i], file_[i].hash, Crypto::kSha256HashLen);

		// copy file to exefs
		memcpy(data_.data() + sizeof(struct sExefsHeader) + offset, file_[i].data, file_[i].size);

		// update offset
		offset += align(file_[i].size, block_size_);
	}

	return 0;
}

int Exefs::SetExefsFile(const char* name, const u8* data, u32 size)
{
	if (file_.size() >= kMaxExefsFileNum) die("[ERROR] Too many files for Exefs.");

	// copy details
	struct sFile file;

	file.name = name;
	file.data = data;
	file.size = size;

	// hash file
	Crypto::Sha256(file.data, file.size, file.hash);
	
	// add file to
	file_.push_back(file);

	return 0;
}