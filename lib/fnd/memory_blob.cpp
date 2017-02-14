#include "memory_blob.h"


MemoryBlob::MemoryBlob() :
	data_(),
	size_(0),
	apparent_size_(0)
{

}

MemoryBlob::~MemoryBlob()
{
}

int MemoryBlob::alloc(size_t size)
{
	int ret = ERR_NONE;
	if (size > size_)
	{
		ret = AllocateMemory(size);
	}
	else
	{
		apparent_size_ = size;
		ClearMemory();
	}
	return ret;
}

int MemoryBlob::extend(size_t new_size)
{
	try {
		data_.resize(new_size);
	}
	catch (...) {
		return ERR_FAILMALLOC;
	}

	return ERR_NONE;
	
	return 0;
}

int MemoryBlob::OpenFile(const char * path)
{
	FILE* fp;
	size_t filesz, filepos;

	if ((fp = fopen(path, "rb")) == NULL)
	{
		return ERR_FAILOPEN;
	}

	fseek(fp, 0, SEEK_END);
	filesz = ftell(fp);
	rewind(fp);

	if (alloc(filesz) != ERR_NONE)
	{
		fclose(fp);
		return ERR_FAILMALLOC;
	}

	for (filepos = 0; filesz > kBlockSize; filesz -= kBlockSize, filepos += kBlockSize)
	{
		fread(data_.data() + filepos, 1, kBlockSize, fp);
	}

	if (filesz)
	{
		fread(data_.data() + filepos, 1, filesz, fp);
	}

	fclose(fp);

	return ERR_NONE;
}

int MemoryBlob::AllocateMemory(size_t size)
{
	size_ = (size_t)align(size, 0x1000);
	apparent_size_ = size;
	data_.resize(size_);
	ClearMemory();
	return ERR_NONE;
}

void MemoryBlob::ClearMemory()
{
	memset(data_.data(), 0, size_);
}
