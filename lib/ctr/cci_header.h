#pragma once
#include <fnd/types.h>
#include <fnd/ByteBuffer.h>
#include <crypto/crypto.h>

class CciHeader
{
public:
	struct sPartitionInfo
	{
		u64 offset;
		u64 size;
		u64 title_id;

		void clear() { memset(this, 0, sizeof(*this)); }
	};

	enum CardDevice
	{
		CARD_DEVICE_NOT_SPECIFIED = 0,
		CARD_DEVICE_NOR_FLASH = 1,
		CARD_DEVICE_NONE = 2,
		CARD_DEVICE_BT = 3,
	};

	enum Platform
	{
		CTR = 1,
		SNAKE = 2,
	};

	enum MediaType
	{
		MEDIA_TYPE_CARD1 = 1,
		MEDIA_TYPE_CARD2 = 2,
	};

	enum CciSectionReservation
	{
		SECTION_EXEC = 0,
		SECTION_EMANUAL = 1,
		SECTION_DLP_CHILD = 2,
		SECTION_SNAKE_UPDATE = 6,
		SECTION_CTR_UPDATE = 7,
	};

	static const int kSectionNum = 8;

	CciHeader();
	CciHeader(const u8* data);
	CciHeader(const CciHeader& other);
	~CciHeader();

	void operator=(const CciHeader& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Header Serialisation
	void SerialiseHeader(const Crypto::sRsa2048Key& ncsd_rsa_key);
	void SetMediaCapacity(u64 size);
	void SetTitleId(u64 title_id);
	void SetBackupWriteWaitTime(u8 time);
	void SetBackupSecurityType(u8 type);
	void SetCardDevice(CardDevice card_device, bool isLegacyCardDevice);
	void SetPlatform(Platform platform);
	void SetMediaType(MediaType media_type);
	void SetBlockSize(u32 block_size);
	void SetPartition(int index, u64 size, u64 title_id);

	// Header Deserialisation
	void DeserialiseHeader(const u8* cci_data);
	bool ValidateSignature(const Crypto::sRsa2048Key& ncsd_rsa_key) const;
	u64 GetMediaCapacity() const;
	u64 GetCciUsedSize() const;
	u64 GetTitleId() const;
	u8 GetBackupWriteWaitTime() const;
	u8 GetBackupSecurityType() const;
	CardDevice GetCardDevice() const;
	bool IsLegacyCardDevice() const;
	Platform GetPlatform() const;
	MediaType GetMediaType() const;
	const sPartitionInfo GetPartition(int index) const;
private:
	const std::string kModuleName = "CCI_HEADER";
	const char kCciStructSignature[4] = { 'N', 'C', 'S', 'D' };
	static const u32 kDefaultBlockSize = 0x200;
	static const uint32_t kDefaultNcchOffset = 0x4000;

	// Private Structures
#pragma pack (push, 1)
	struct sSectionGeometry
	{
	private:
		u32 offset_;
		u32 size_;
	public:
		u32 offset() const { return le_word(offset_); }
		u32 size() const { return le_word(size_); }

		void set_offset(u32 offset) { offset_ = le_word(offset); }
		void set_size(u32 size) { size_ = le_word(size); }
	};

	struct sCciHeader
	{
	private:
		char struct_signature_[4];
		u32 size_;
		u64 title_id_;
		u8 section_fs_type_[kSectionNum];
		u8 section_crypto_type_[kSectionNum];
		sSectionGeometry content_[kSectionNum];
		u8 extended_header_hash[Crypto::kSha256HashLen];
		u32 additional_header_size;
		u32 sector0_offset;
		struct sFlags
		{
			u8 backup_write_wait_time_;
			u8 backup_security_type_;
			u8 reserved;
			u8 card_device_;
			u8 platform_;
			u8 media_type_;
			u8 block_size_;
			u8 card_device_old_;
		} flags_;
		u64 content_title_ids_[kSectionNum];
		u8 reserved2[0x30];
	public:
		const char* struct_signature() const { return struct_signature_; }
		u32 size() const { return le_word(size_); }
		u64 title_id() const { return le_dword(title_id_); }
		const sSectionGeometry& content(int index) const { return content_[index]; }
		u8 backup_write_wait_time() const { return flags_.backup_write_wait_time_; }
		u8 backup_security_type() const { return flags_.backup_security_type_; }
		CardDevice card_device() const { return (CardDevice)flags_.card_device_; }
		Platform platform() const { return (Platform)flags_.platform_; }
		MediaType media_type() const { return (MediaType)flags_.media_type_; }
		CardDevice card_device_old() const { return (CardDevice)flags_.card_device_old_; }
		u8 block_size() const { return flags_.block_size_; }
		u64 content_title_id(int index) const { return le_dword(content_title_ids_[index]); }

		void clear() { memset(this, 0, sizeof(sCciHeader)); }

		void set_struct_signature(const char signature[4]) { memcpy(struct_signature_, signature, 4); }
		void set_size(u32 size) { size_ = le_word(size); }
		void set_title_id(u64 title_id) { title_id_ = le_dword(title_id); }
		void set_content(int index, u32 offset, u32 size) { content_[index].set_offset(offset); content_[index].set_size(size); }
		void set_backup_write_wait_time(u8 time) { flags_.backup_write_wait_time_ = time; }
		void set_backup_security_type(u8 type) { flags_.backup_security_type_ = type; }
		void set_card_device(CardDevice card_device) { flags_.card_device_ = card_device; }
		void set_platform(Platform platform) { flags_.platform_ = platform; }
		void set_media_type(MediaType media_type) { flags_.media_type_ = media_type; }
		void set_block_size(u8 block_size) { flags_.block_size_ = block_size; }
		void set_card_device_old(CardDevice card_device) { flags_.card_device_old_ = card_device; }
		void set_content_title_id(int index, u64 title_id) { content_title_ids_[index] = le_dword(title_id); }
	};

	struct sSignedCciHeader
	{
		u8 rsa_signature[Crypto::kRsa2048Size];
		sCciHeader body;
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;


	void FinaliseCciLayout();
	u32 SizeToBlockNum(u64 size);
	u64 BlockNumToSize(u32 block_num);

	// sections
	sPartitionInfo sections_[kSectionNum];

	// variables
	u64 media_capacity_;
	u64 cci_used_size_;
	u64 title_id_;
	u8 backup_write_wait_time_;
	u8 backup_security_type_;
	CardDevice card_device_;
	bool is_old_card_device_;
	Platform platform_;
	MediaType media_type_;
	u32 block_size_;
	u32 block_size_bit_;

	void ClearDeserialisedVariables();
};

