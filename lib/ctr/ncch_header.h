#pragma once
#include <fnd/types.h>
#include <fnd/memory_blob.h>
#include <crypto/crypto.h>

class NcchHeader
{
public:
	// Public enums
	enum FormatVersion
	{
		NCCH_FORMAT_0, // prototype NCCH format
		NCCH_FORMAT_1, // current NCCH format
	};

	enum FormType
	{
		UNASSIGNED,
		SIMPLE_CONTENT,
		EXECUTABLE_WITHOUT_ROMFS,
		EXECUTABLE
	};

	enum ContentType
	{
		APPLICATION,
		SYSTEM_UPDATE,
		MANUAL,
		CHILD,
		TRIAL,
		EXTENDED_SYSTEM_UPDATE
	};

	enum Platform
	{
		CTR = 1,
		SNAKE = 2
	};

	// Constructor/Destructor
	NcchHeader();
	NcchHeader(const u8* data);
	NcchHeader(const NcchHeader& other);
	~NcchHeader();

	void operator=(const NcchHeader& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Header Serialisation
	void SerialiseHeader(const Crypto::sRsa2048Key& ncch_rsa_key);
	void SerialiseHeader(const Crypto::sRsa2048Key& ncch_rsa_key, FormatVersion format_version);
	void SetTitleId(u64 title_id);
	void SetProgramId(u64 program_id);
	void SetCompanyCode(const char* maker_code);
	void SetProductCode(const char* product_code);
	void SetPlatform(Platform platorm);
	void SetFormType(FormType type); // consider private
	void SetContentType(ContentType type);
	void SetBlockSize(u32 size);
	void DisableEncryption();
	void EnableEncryption(bool is_fixed_key, u8 keyx_id);
	void DisablePreload();
	void EnablePreload(const u8 preload_seed[Crypto::kAes128KeySize], bool disclose_manual);
	void SetExheaderData(u32 size, u32 accessdesc_size, const u8 hash[Crypto::kSha256HashLen]);
	void SetPlainRegionData(u32 size);
	void SetLogoData(u32 size, const u8 hash[Crypto::kSha256HashLen]);
	void SetExefsData(u64 size, u32 hashedDataSize, const u8 hash[Crypto::kSha256HashLen]);
	void SetRomfsData(u64 size, u32 hashedDataSize, const u8 hash[Crypto::kSha256HashLen]);
	

	// Header Deserialisation
	void DeserialiseHeader(const u8* ncch_data);
	bool ValidateSignature(const Crypto::sRsa2048Key& ncch_rsa_key) const;
	bool ValidatePreloadSeed(const u8 seed[Crypto::kAes128KeySize]);
	u64 GetNcchSize() const;
	u64 GetTitleId() const;
	const std::string& GetCompanyCode() const;
	FormatVersion GetFormatVersion() const;
	u64 GetProgramId() const;
	const u8* GetLogoHash() const;
	const std::string& GetProductCode() const;
	const u8* GetExheaderHash() const;
	u32 GetExheaderSize() const;
	u8 GetKeyId() const;
	Platform GetPlatform() const;
	FormType GetFormType() const;
	ContentType GetContentType() const;
	bool IsEncrypted() const;
	bool IsFixedAesKey() const;
	bool HasPreloadSeed() const;
	bool IsPreloadManualDisclosed() const;
	u64 GetPlainRegionOffset() const;
	u64 GetPlainRegionSize() const;
	u64 GetLogoOffset() const;
	u64 GetLogoSize() const;
	u64 GetExefsOffset() const;
	u64 GetExefsSize() const;
	u64 GetExefsHashedRegionSize() const;
	u64 GetRomfsOffset() const;
	u64 GetRomfsSize() const;
	u64 GetRomfsHashedRegionSize() const;
	const u8* GetExefsHash() const;
	const u8* GetRomfsHash() const;

protected:
	u32 GetSeedChecksum() const; // consider private
	u32 GetBlockSize() const; // consider private

private:
	const std::string kModuleName = "NCCH_HEADER";
	const char kNcchStructSignature[4] = { 'N', 'C', 'C', 'H' };
	static const FormatVersion kDefaultFormatVersion = NCCH_FORMAT_1;
	static const u32 kDefaultBlockSize = 0x200;
	static const int kCompanyCodeLen = 0x2;
	static const int kProductCodeLen = 0x10;

	enum NcchFormatId
	{
		NCCH_CFA = 0,
		NCCH_PROTOTYPE = 1,
		NCCH_CXI = 2,
	};

	enum OtherFlag
	{
		FIXED_AES_KEY = 0,
		NO_MOUNT_ROMFS = 1,
		NO_AES = 2,
		SEED_KEY = 5,
		MANUAL_DISCLOSURE = 6,
	};
	
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

	struct sHashedSectionGeometry : sSectionGeometry
	{
	private:
		u32 hashed_size_;
	public:
		u32 hashed_size() const { return le_word(hashed_size_); }
		void set_hashed_size(u32 size) { hashed_size_ = le_word(size); }
	};

	struct sNcchHeader
	{
	private:
		char struct_signature_[4];
		u32 size_;
		u64 title_id_;
		char company_code_[kCompanyCodeLen];
		u16 format_id_;
		u32 seed_checksum_;
		u64 program_id_;
		u8 reserved1_[0x10];
		u8 logo_hash_[Crypto::kSha256HashLen];
		char product_code_[kProductCodeLen];
		u8 exheader_hash_[Crypto::kSha256HashLen];
		u32 exheader_size_;
		u8 reserved2_[0x4];
		struct sFlags
		{
			u8 reserved[3];
			u8 key_id;
			u8 platform;
			u8 content_type;
			u8 block_size;
			u8 other_flag;
		} flags_;
		sSectionGeometry plain_region_;
		sSectionGeometry logo_;
		sHashedSectionGeometry exefs_;
		u8 reserved3_[4];
		sHashedSectionGeometry romfs_;
		u8 reserved4_[4];
		u8 exefs_hash_[Crypto::kSha256HashLen];
		u8 romfs_hash_[Crypto::kSha256HashLen];
	public:
		const char* struct_signature() const { return struct_signature_; }
		u32 size() const { return le_word(size_); }
		u64 title_id() const { return le_dword(title_id_); }
		const char* company_code() const { return company_code_; }
		NcchFormatId format_id() const { return (NcchFormatId)le_hword(format_id_); }
		u32 seed_checksum() const { return le_word(seed_checksum_); }
		u64 program_id() const { return le_dword(program_id_); }
		const u8* logo_hash() const { return logo_hash_; }
		const char* product_code() const { return product_code_; }
		const u8* exheader_hash() const { return exheader_hash_; }
		u32 exheader_size() const { return le_word(exheader_size_); }
		u8 key_id() const { return flags_.key_id; }
		Platform platform() const { return (Platform)flags_.platform; }
		FormType form_type() const { return (FormType)(flags_.content_type & 3); }
		ContentType content_type() const { return (ContentType)(flags_.content_type >> 2); }
		u8 block_size() const { return flags_.block_size; }
		u8 other_flag() const { return flags_.other_flag; }
		bool other_flag_bit(u8 bit) const { return ((flags_.other_flag > bit) & 1) == true; }
		const sSectionGeometry& plain_region() const { return plain_region_; }
		const sSectionGeometry& logo() const { return logo_; }
		const sHashedSectionGeometry& exefs() const { return exefs_; }
		const sHashedSectionGeometry& romfs() const { return romfs_; }
		const u8* exefs_hash() const { return exefs_hash_; }
		const u8* romfs_hash() const { return romfs_hash_; }

		void clear() { memset(this, 0, sizeof(sNcchHeader)); }

		void set_struct_signature(const char signature[4]) { strncpy(struct_signature_, signature, 4); }
		void set_size(u32 size) { size_ = le_word(size); }
		void set_title_id(u64 title_id) { title_id_ = le_dword(title_id); }
		void set_company_code(const char company_code[kCompanyCodeLen]) { memcpy(company_code_, company_code, kCompanyCodeLen); }
		void set_format_id(NcchFormatId id) { format_id_ = le_hword((u16)id); }
		void set_seed_checksum(u32 checksum) { seed_checksum_ = le_word(checksum); }
		void set_program_id(u64 program_id) { program_id_ = le_dword(program_id); }
		void set_logo_hash(const u8 hash[Crypto::kSha256HashLen]) { memcpy(logo_hash_, hash, Crypto::kSha256HashLen); }
		void set_product_code(const char* product_code, size_t len) { memcpy(product_code_, product_code, len < kProductCodeLen ? len : kProductCodeLen); }
		void set_exheader_hash(const u8 hash[Crypto::kSha256HashLen]) { memcpy(exheader_hash_, hash, Crypto::kSha256HashLen); }
		void set_exheader_size(u32 size) { exheader_size_ = le_word(size); }
		void set_key_id(u8 id) { flags_.key_id = id; }
		void set_platform(Platform platform) { flags_.platform = platform; }
		void set_form_type(FormType type) { flags_.content_type &= ~3; flags_.content_type |= (type & 3); }
		void set_content_type(ContentType type) { flags_.content_type &= 3; flags_.content_type |= (type << 2); }
		void set_block_size(u8 size) { flags_.block_size = size; }
		void set_other_flag(u8 flag) { flags_.other_flag = flag; }
		void set_other_flag_bit(u8 bit, bool enable) { enable? flags_.other_flag |= BIT(bit) : flags_.other_flag &= ~BIT(bit); }
		void set_plain_region(u32 offset, u32 size) { plain_region_.set_offset(offset); plain_region_.set_size(size); }
		void set_logo(u32 offset, u32 size) { logo_.set_offset(offset); logo_.set_size(size); }
		void set_exefs(u32 offset, u32 size, u32 hashed_size) { exefs_.set_offset(offset); exefs_.set_size(size); exefs_.set_hashed_size(hashed_size); }
		void set_romfs(u32 offset, u32 size, u32 hashed_size) { romfs_.set_offset(offset); romfs_.set_size(size); romfs_.set_hashed_size(hashed_size); }
		void set_exefs_hash(const u8 hash[Crypto::kSha256HashLen]) { memcpy(exefs_hash_, hash, Crypto::kSha256HashLen); }
		void set_romfs_hash(const u8 hash[Crypto::kSha256HashLen]) { memcpy(romfs_hash_, hash, Crypto::kSha256HashLen); }
	};

	struct sSignedNcchHeader
	{
		u8 rsa_signature[Crypto::kRsa2048Size];
		sNcchHeader body;

		void clear() { memset(this, 0, sizeof(sSignedNcchHeader)); }
	};

	struct sSeedValidateStruct
	{
	private:
		u8 seed_[Crypto::kAes128KeySize];
		u64 program_id_;
	public:
		u32 seed_checksum()
		{
			u8 hash[Crypto::kSha256HashLen];
			Crypto::Sha256((const u8*)this, sizeof(sSeedValidateStruct), hash);
			return le_word(*((u32*)(hash)));
		}

		void clear() { memset(this, 0, sizeof(sSeedValidateStruct)); }

		void set_seed(const u8* seed) { memcpy(seed_, seed, Crypto::kSha256HashLen); }
		void set_program_id(u64 program_id) { program_id_ = le_dword(program_id); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	/*
	struct sNcchHeader header_;
	u32 access_descriptor_size_;
	
	inline u32 block_size() const { return 1 << (header_.flags.block_size + 9); }
	*/
	
	void FinaliseNcchLayout();
	u32 SizeToBlockNum(u64 size);
	u64 BlockNumToSize(u32 block_num);

	struct sNcchSection {
		u64 size;
		u64 offset;
		u64 hashed_size;
		u8 hash[Crypto::kSha256HashLen];

		void set_hash(const u8 in_hash[Crypto::kSha256HashLen]) { memcpy(hash, in_hash, Crypto::kSha256HashLen); }
		void clear() { memset(this, 0, sizeof(sNcchSection)); }
	};

	// sections
	sNcchSection exheader_;
	sNcchSection access_descriptor_;
	sNcchSection plain_region_;
	sNcchSection logo_;
	sNcchSection exefs_;
	sNcchSection romfs_;

	// variables
	u64 ncch_binary_size_;
	NcchFormatId format_id_;
	u64 title_id_;
	u64 program_id_;
	u32 seed_checksum_;
	std::string company_code_;
	std::string product_code_;
	u8 key_id_;
	Platform platform_;
	FormType form_type_;
	ContentType content_type_;
	u32 block_size_;
	u32 block_size_bit_;
	bool is_encrypted_;
	bool is_fixed_aes_key_;
	bool is_seeded_keyy_;
	bool is_manual_disclosed_;
	u8 preload_seed_[Crypto::kAes128KeySize];

	void ClearDeserialisedVariables();
};

