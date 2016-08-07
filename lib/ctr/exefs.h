#pragma once
#include <vector>
#include "types.h"
#include "ByteBuffer.h"
#include "crypto.h"

class Exefs
{
public:
	Exefs();
	~Exefs();

	// trigger internal exefs creation
	int CreateExefs();

	// add files to Exefs
	int SetExefsFile(const char* name, const u8* data, u32 size);
	
	// data extraction
	inline const u8* data_blob() const { return data_.data_const(); }
	inline u32 data_size() const { return data_.size(); }
private:
	static const int kDefaultBlockSize = 0x200;
	static const int kMaxExefsFileNameLen = 8;
	static const int kMaxExefsFileNum = 8;

	struct sFile
	{
		const u8 *data;
		const char *name;
		u32 size;
		u8 hash[Crypto::kSha256HashLen];
	};

	struct sExefsHeader
	{
		struct sFileEntry
		{
			char name[kMaxExefsFileNameLen];
			u32 offset;
			u32 size;
		} files[kMaxExefsFileNum];
		u8 reserved[0x80];
		u8 fileHashes[kMaxExefsFileNum][Crypto::kSha256HashLen];
	};

	u32 block_size_;
	std::vector<struct sFile> file_;
	ByteBuffer data_;
};