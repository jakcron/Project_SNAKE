#pragma once
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "types.h"

class ByteBuffer
{
public:
	enum ErrorCode
	{
		ERR_NONE,
		ERR_FAILOPEN,
		ERR_FAILMALLOC,
		ERR_FAILREAD,
	};

	ByteBuffer() :
		data_(NULL),
		size_(0),
		apparent_size_(0)
	{

	}

	~ByteBuffer()
	{
		FreeMemory();
	}

	int alloc(size_t size)
	{
		if (size > size_)
		{
			FreeMemory();
			return AllocateMemory(size);
		}
		else
		{
			apparent_size_ = size;
			ClearMemory();
		}
		return ERR_NONE;
	}

	int OpenFile(const char* path)
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

		for (filepos=0; filesz > kBlockSize; filesz -= kBlockSize, filepos += kBlockSize)
		{
			fread(data_ + filepos, 1, kBlockSize, fp);
		}

		if (filesz)
		{
			fread(data_ + filepos, 1, filesz, fp);
		}

		fclose(fp);

		return ERR_NONE;
	}

	inline byte_t* data() { return data_; }
	inline const byte_t* data_const() const { return data_; }
	inline size_t size() const { return apparent_size_; }

private:
	static const size_t kBlockSize = 0x100000;

	byte_t* data_;
	size_t size_;
	size_t apparent_size_;

	void FreeMemory()
	{
		free(data_);
		size_ = 0;
		apparent_size_ = 0;
	}

	int AllocateMemory(size_t size)
	{
		size_ = (size_t)align(size,0x1000);
		apparent_size_ = size;
		if ((data_ = (byte_t*)malloc(size_)) == NULL)
		{
			return ERR_FAILMALLOC;
		}
		ClearMemory();
		return ERR_NONE;
	}

	void ClearMemory()
	{
		memset(data_, 0, size_);
	}
};