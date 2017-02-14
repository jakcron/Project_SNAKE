#include "exefs_header.h"



ExefsHeader::ExefsHeader()
{
	ClearDeserialisedVariables();
}

ExefsHeader::ExefsHeader(const u8 * data)
{
	DeserialiseData(data);
}

ExefsHeader::ExefsHeader(const ExefsHeader & other)
{
	DeserialiseData(other.GetSerialisedData());
}


ExefsHeader::~ExefsHeader()
{
}

void ExefsHeader::operator=(const ExefsHeader & other)
{
	DeserialiseData(other.GetSerialisedData());
}

const u8 * ExefsHeader::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t ExefsHeader::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void ExefsHeader::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sExefsHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	sExefsHeader* hdr = (sExefsHeader*)serialised_data_.data();

	if (align_size_ == 0)
	{
		align_size_ = kDefaultAlignSize;
	}

	size_t pos = 0;
	for (size_t i = 0; i < files_.size() && i < kExefsFileNum; i++)
	{
		files_[i].offset = pos;
		pos += align(pos + files_[i].size, align_size_);

		hdr->set_name(i, files_[i].name.c_str());
		hdr->set_offset(i, files_[i].offset);
		hdr->set_size(i, files_[i].size);
		hdr->set_hash(i, files_[i].hash);
	}

	pos = align(pos, align_size_);

	exefs_size_ = sizeof(sExefsHeader) + pos;
}

void ExefsHeader::SetAlignSize(u32 size)
{
	align_size_ = size;
}

void ExefsHeader::AddExefsFile(const std::string & name, u32 size, u8 hash[Crypto::kSha256HashLen])
{
	if (name.size() > kExefsFileNameLength)
	{
		throw ProjectSnakeException(kModuleName, "Exefs file name too long. (max 8 characters)");
	}
	if (files_.size() > kExefsFileNum)
	{
		throw ProjectSnakeException(kModuleName, "Too many exefs files. (max 8 files)");
	}

	sExefsFile file;
	file.name = name;
	file.offset = 0;
	file.size = size;
	memcpy(file.hash, hash, Crypto::kSha256HashLen);
}

void ExefsHeader::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();

	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sExefsHeader)) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}
	memcpy(serialised_data_.data(), data, sizeof(sExefsHeader));

	const sExefsHeader* hdr = (const sExefsHeader*)serialised_data_.data_const();

	if (align_size_ == 0)
	{
		align_size_ = kDefaultAlignSize;
	}

	sExefsFile file;
	size_t latest_file_ = 0;
	for (size_t i = 0; i < kExefsFileNum && hdr->size(i) != 0; i++)
	{
		if (hdr->offset(i) + hdr->size(i) > hdr->offset(latest_file_) + hdr->size(latest_file_))
		{
			latest_file_ = i;
		}

		file.name = std::string(hdr->name(i), kExefsFileNameLength);
		file.offset = hdr->offset(i);
		file.size = hdr->size(i);
		memcpy(file.hash, hdr->hash(i), Crypto::kSha256HashLen);
		files_.push_back(file);
	}

	exefs_size_ = align(hdr->offset(latest_file_) + hdr->size(latest_file_), align_size_);
}

size_t ExefsHeader::GetExefsSize() const
{
	return exefs_size_;
}

const std::vector<ExefsHeader::sExefsFile>& ExefsHeader::GetExefsFiles() const
{
	return files_;
}

void ExefsHeader::ClearDeserialisedVariables()
{
	align_size_ = 0;
	exefs_size_ = 0;
	files_.clear();
}
