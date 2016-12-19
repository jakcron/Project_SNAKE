#include <cmath>
#include "cci_header.h"



CciHeader::CciHeader()
{
	ClearDeserialisedVariables();
}

CciHeader::CciHeader(const u8 * data)
{
	DeserialiseHeader(data);
}

CciHeader::CciHeader(const CciHeader & other)
{
	DeserialiseHeader(other.GetSerialisedData());
}


CciHeader::~CciHeader()
{
}

void CciHeader::operator=(const CciHeader & other)
{
	DeserialiseHeader(other.GetSerialisedData());
}

const u8 * CciHeader::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t CciHeader::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void CciHeader::SerialiseHeader(const Crypto::sRsa2048Key & ncsd_rsa_key)
{
	// allocate memory for header
	if (serialised_data_.alloc(sizeof(sSignedCciHeader)))
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for CCI header");
	}

	sSignedCciHeader* hdr = (sSignedCciHeader*)(serialised_data_.data());

	// set block size
	block_size_bit_ = log2l(block_size_) - 9;
	if (BIT(block_size_bit_) != block_size_)
	{
		throw ProjectSnakeException(kModuleName, "Block size is invalid CCI (must be a power of 2, starting at 512 bytes)");
	}
	hdr->body.set_block_size(block_size_bit_ - 9);

	// set property variables
	hdr->body.set_struct_signature(kCciStructSignature);
	hdr->body.set_title_id(title_id_);
	hdr->body.set_backup_write_wait_time(backup_write_wait_time_);
	hdr->body.set_backup_security_type(backup_security_type_);
	if (is_old_card_device_)
	{
		hdr->body.set_card_device_old(card_device_);
	}
	else
	{
		hdr->body.set_card_device(card_device_);
	}
	hdr->body.set_platform(platform_);
	hdr->body.set_media_type(media_type_);

	// set cci layout
	FinaliseCciLayout();
	hdr->body.set_size(SizeToBlockNum(media_capacity_));
	for (int i = 0; i < kSectionNum; i++)
	{
		hdr->body.set_content(i, SizeToBlockNum(sections_[i].offset), SizeToBlockNum(sections_[i].size));
		hdr->body.set_content_title_id(i, sections_[i].title_id);
	}

	// sign header
	u8 hash[Crypto::kSha256HashLen];
	Crypto::Sha256((const u8*)&hdr->body, sizeof(sCciHeader), hash);

	Crypto::RsaSign(ncsd_rsa_key, Crypto::HASH_SHA256, hash, hdr->rsa_signature);
}

void CciHeader::SetMediaCapacity(u64 size)
{
	media_capacity_ = size;
}

void CciHeader::SetTitleId(u64 title_id)
{
	title_id_ = title_id;
}

void CciHeader::SetBackupWriteWaitTime(u8 time)
{
	backup_write_wait_time_ = time;
}

void CciHeader::SetBackupSecurityType(u8 type)
{
	backup_security_type_ = type;
}

void CciHeader::SetCardDevice(CardDevice card_device, bool isLegacyCardDevice)
{
	card_device_ = card_device;
	is_old_card_device_ = isLegacyCardDevice;
}

void CciHeader::SetPlatform(Platform platform)
{
	platform_ = platform;
}

void CciHeader::SetMediaType(MediaType media_type)
{
	media_type_ = media_type;
}

void CciHeader::SetBlockSize(u32 block_size)
{
	block_size_ = block_size;
}

void CciHeader::SetPartition(int index, u64 size, u64 title_id)
{
	if (index < 0 || index >= kSectionNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal CCI partition index");
	}

	sections_[index].size = size;
	sections_[index].title_id = title_id;
}

void CciHeader::DeserialiseHeader(const u8 * cci_data)
{
	ClearDeserialisedVariables();
	// allocate and save a copy of serialised data
	if (serialised_data_.alloc(sizeof(sSignedCciHeader)))
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for CCI header");
	}

	// get pointer to header struct
	memcpy(serialised_data_.data(), cci_data, serialised_data_.size());

	const sSignedCciHeader* hdr = (const sSignedCciHeader*)(serialised_data_.data_const());

	// validate header bytes
	if (memcmp(hdr->body.struct_signature(), kCciStructSignature, 4) != 0)
	{
		throw ProjectSnakeException(kModuleName, "CCI header is corrupt");
	}

	// get block size
	block_size_bit_ = hdr->body.block_size() + 9;
	block_size_ = 1 << block_size_bit_;

	// deserialise header
	media_capacity_ = BlockNumToSize(hdr->body.size());
	title_id_ = hdr->body.title_id();
	backup_write_wait_time_ = hdr->body.backup_write_wait_time();
	backup_security_type_ = hdr->body.backup_security_type();
	if (hdr->body.card_device() != CARD_DEVICE_NOT_SPECIFIED)
	{
		card_device_ = hdr->body.card_device();
		is_old_card_device_ = false;
	}
	else if (hdr->body.card_device_old() != CARD_DEVICE_NOT_SPECIFIED)
	{
		card_device_ = hdr->body.card_device_old();
		is_old_card_device_ = true;
	}
	else
	{
		// warn??
		card_device_ = CARD_DEVICE_NOT_SPECIFIED;
		is_old_card_device_ = true;
	}
	platform_ = hdr->body.platform();
	media_type_ = hdr->body.media_type();

	// validate mediatype
	if (media_type_ != MEDIA_TYPE_CARD1 && media_type_ != MEDIA_TYPE_CARD2)
	{
		throw ProjectSnakeException(kModuleName, "CCI header has unsupported media type");
	}

	// content
	for (int i = 0; i < kSectionNum; i++)
	{
		// skip empty content
		if (hdr->body.content(i).size() == 0)
		{
			sections_[i].offset = 0;
			sections_[i].size = 0;
			sections_[i].title_id = 0;
			continue;
		}

		// save content info
		sections_[i].offset = BlockNumToSize(hdr->body.content(i).offset());
		sections_[i].size = BlockNumToSize(hdr->body.content(i).size());
		sections_[i].title_id = hdr->body.content_title_id(i);

		// update cci used size
		if (sections_[i].offset + sections_[i].size > cci_used_size_)
		{
			cci_used_size_ = sections_[i].offset + sections_[i].size;
		}

	}
}

bool CciHeader::ValidateSignature(const Crypto::sRsa2048Key & ncsd_rsa_key) const
{
	const struct sSignedCciHeader* data = (const struct sSignedCciHeader*)serialised_data_.data_const();

	// hash header
	u8 hash[Crypto::kSha256HashLen];
	Crypto::Sha256((const u8*)&data->body, sizeof(sCciHeader), hash);

	return Crypto::RsaVerify(ncsd_rsa_key, Crypto::HASH_SHA256, hash, data->rsa_signature) == 0;
}

u64 CciHeader::GetMediaCapacity() const
{
	return media_capacity_;
}

u64 CciHeader::GetCciUsedSize() const
{
	return cci_used_size_;
}

u64 CciHeader::GetTitleId() const
{
	return title_id_;
}

u8 CciHeader::GetBackupWriteWaitTime() const
{
	return backup_write_wait_time_;
}

u8 CciHeader::GetBackupSecurityType() const
{
	return backup_security_type_;
}

CciHeader::CardDevice CciHeader::GetCardDevice() const
{
	return card_device_;
}

bool CciHeader::IsLegacyCardDevice() const
{
	return is_old_card_device_;
}

CciHeader::Platform CciHeader::GetPlatform() const
{
	return platform_;
}

CciHeader::MediaType CciHeader::GetMediaType() const
{
	return media_type_;
}

const CciHeader::sPartitionInfo CciHeader::GetPartition(int index) const
{
	if (index < 0 || index >= kSectionNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal CCI partition index");
	}

	return sections_[index];
}

void CciHeader::FinaliseCciLayout()
{
	u64 size = kDefaultNcchOffset;

	for (int i = 0; i < kSectionNum; i++)
	{
		if (sections_[i].size > 0)
		{
			sections_[i].offset = size;
			size += align(sections_[i].size, block_size_);
		}
		else
		{
			// clear
			sections_[i].size = 0;
			sections_[i].offset = 0;
			sections_[i].title_id = 0;
		}
	}

	cci_used_size_ = size;
}

u32 CciHeader::SizeToBlockNum(u64 size)
{
	return (u32)(align(size, block_size_) >> block_size_bit_);
}

u64 CciHeader::BlockNumToSize(u32 block_num)
{
	return ((u64)block_num) << block_size_bit_;;
}

void CciHeader::ClearDeserialisedVariables()
{
	for (int i = 0; i < kSectionNum; i++)
	{
		sections_[i].clear();
	}
	media_capacity_ = 0;
	cci_used_size_ = 0;
	title_id_ = 0;
	backup_write_wait_time_ = 0;
	backup_security_type_ = 0;
	card_device_ = CARD_DEVICE_NOT_SPECIFIED;
	is_old_card_device_ = false;
	platform_ = CTR;
	media_type_ = MediaType::MEDIA_TYPE_CARD1;
	block_size_ = 0;
	block_size_bit_ = 0;
}
