#include <cstdio>
#include <cstring>
#include <cmath>
#include "ncch_header.h"

NcchHeader::NcchHeader()
{
	SetBlockSize(kDefaultBlockSize);
}

NcchHeader::~NcchHeader()
{

}

void NcchHeader::operator=(const NcchHeader & other)
{
	DeserialiseHeader(other.GetSerialisedData());
}

const u8 * NcchHeader::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t NcchHeader::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void NcchHeader::SerialiseHeader(const Crypto::sRsa2048Key& ncch_rsa_key)
{
	SerialiseHeader(ncch_rsa_key, NCCH_FORMAT_1);
}

void NcchHeader::SerialiseHeader(const Crypto::sRsa2048Key& ncch_rsa_key, FormatVersion format_version)
{
	// allocate memory for header
	serialised_data_.alloc(Crypto::kRsa2048Size + sizeof(sNcchHeader));

	// pointers in the serialised data
	u8* rsaSignature = serialised_data_.data();
	sNcchHeader* hdr = (sNcchHeader*)(serialised_data_.data() + Crypto::kRsa2048Size);

	if (format_version == NCCH_FORMAT_0) 
	{
		format_version_ = 1;

		if (block_size_ >= 0x100) 
		{
			throw ProjectSnakeException(kModuleName, "Block size is invalid for current NCCH format");
		}

		hdr->set_block_size(block_size_);
	}
	else if (format_version == NCCH_FORMAT_1)
	{
		format_version_ = form_type_ == FormType::SIMPLE_CONTENT ? 0 : 2;
		block_size_bit_ = log2l(block_size_) - 9;
		if (BIT(block_size_bit_) != block_size_) 
		{
			throw ProjectSnakeException(kModuleName, "Block size is invalid for current NCCH format");
		}
		hdr->set_block_size(block_size_bit_ - 9);
	}

	// set property variables
	hdr->set_struct_signature(kNcchStructSignature);
	hdr->set_title_id(title_id_);
	hdr->set_company_code(company_code_.c_str());
	hdr->set_format_version(format_version_);
	hdr->set_seed_checksum(seed_checksum_);
	hdr->set_program_id(program_id_);
	hdr->set_logo_hash(logo_.hash);
	hdr->set_product_code(product_code_.c_str(), product_code_.length());
	hdr->set_key_id(key_id_);
	hdr->set_platform(platform_);
	hdr->set_content_type(content_type_);
	hdr->set_other_flag(0);
	hdr->set_other_flag_bit(NO_MOUNT_ROMFS, romfs_.size == 0);

	// set form type
	if (exefs_.size > 0) 
	{
		form_type_ = romfs_.size > 0 ? FormType::EXECUTABLE : FormType::EXECUTABLE_WITHOUT_ROMFS;
	}
	else if (romfs_.size > 0)
	{
		form_type_ = FormType::SIMPLE_CONTENT;
	}
	else
	{
		form_type_ = FormType::UNASSIGNED;
	}
	hdr->set_form_type(form_type_);


	// set encryption parameters
	if (is_encrypted_) 
	{
		if (is_fixed_aes_key_) 
		{
			hdr->set_other_flag_bit(FIXED_AES_KEY, is_fixed_aes_key_);
			hdr->set_key_id(0);
		}
		else
		{
			hdr->set_key_id(key_id_);
			hdr->set_other_flag_bit(SEED_KEY, is_seeded_keyy_);
			if (is_seeded_keyy_)
			{
				hdr->set_other_flag_bit(MANUAL_DISCLOSURE, is_manual_disclosed_);
			}
			
		}
	}
	else
	{
		hdr->set_other_flag_bit(NO_AES, false);
		hdr->set_key_id(0);
	}

	

	// set layout variables
	FinaliseNcchLayout();
	hdr->set_size(SizeToBlockNum(ncch_binary_size_));
	if (exheader_.size) 
	{
		hdr->set_exheader_hash(exheader_.hash);
		hdr->set_exheader_size(exheader_.size);
	}
	if (plain_region_.size)
	{
		hdr->set_plain_region(SizeToBlockNum(plain_region_.offset), SizeToBlockNum(plain_region_.size));
	}
	if (logo_.size)
	{
		hdr->set_logo(SizeToBlockNum(logo_.offset), SizeToBlockNum(logo_.size));
		hdr->set_logo_hash(logo_.hash);
	}
	if (exefs_.size)
	{
		hdr->set_exefs(SizeToBlockNum(exefs_.offset), SizeToBlockNum(exefs_.size), SizeToBlockNum(exefs_.hashed_size));
		hdr->set_exefs_hash(exefs_.hash);
	}
	if (romfs_.size)
	{
		hdr->set_romfs(SizeToBlockNum(romfs_.offset), SizeToBlockNum(romfs_.size), SizeToBlockNum(romfs_.hashed_size));
		hdr->set_romfs_hash(romfs_.hash);
	}
	
	// sign header
	u8 hash[Crypto::kSha256HashLen];
	Crypto::RsaSign(ncch_rsa_key, Crypto::HASH_SHA256, hash, rsaSignature);
}

// Basic Data
void NcchHeader::SetTitleId(u64 title_id)
{
	title_id_ = title_id;
}

void NcchHeader::SetProgramId(u64 program_id)
{
	program_id_ = program_id;
}

void NcchHeader::SetCompanyCode(const char* company_code)
{
	company_code_ = std::string(company_code, kCompanyCodeLen);
}

void NcchHeader::SetProductCode(const char* product_code)
{
	product_code_ = std::string(product_code, kProductCodeLen);
}

// Flags
void NcchHeader::SetPlatform(NcchHeader::Platform platform)
{
	platform_ = platform;
}

void NcchHeader::SetFormType(FormType type)
{
	form_type_ = type;
}

void NcchHeader::SetContentType(ContentType type)
{
	content_type_ = type;
}

void NcchHeader::SetBlockSize(u32 size)
{
	block_size_ = size;
	block_size_bit_ = log2l(size) - 9;
}

void NcchHeader::DisableEncryption()
{
	is_encrypted_ = false;
}

void NcchHeader::EnableEncryption(bool is_fixed_key, u8 keyx_id)
{
	is_encrypted_ = true;
	is_fixed_aes_key_ = is_fixed_key;
	key_id_ = keyx_id;
}

void NcchHeader::DisablePreload()
{
	is_seeded_keyy_ = false;
	is_manual_disclosed_ = false;
	memset(preload_seed_, 0, Crypto::kAes128KeySize);
}

void NcchHeader::EnablePreload(const u8 preload_seed[Crypto::kAes128KeySize], bool disclose_manual)
{
	is_seeded_keyy_ = true;
	is_manual_disclosed_ = disclose_manual;
	memcpy(preload_seed_, preload_seed, Crypto::kAes128KeySize);
}

// Data segments
void NcchHeader::SetExheaderData(u32 size, u32 accessdesc_size, const u8 hash[Crypto::kSha256HashLen])
{
	exheader_.size = size;
	memcpy(exheader_.hash, hash, Crypto::kSha256HashLen);
	access_descriptor_.size = accessdesc_size;
}

void NcchHeader::SetPlainRegionData(u32 size)
{
	plain_region_.size = size;
}

void NcchHeader::SetLogoData(u32 size, const u8 hash[Crypto::kSha256HashLen])
{
	logo_.size = size;
	memcpy(logo_.hash, hash, Crypto::kSha256HashLen);
}

void NcchHeader::SetExefsData(u32 size, u32 hashed_data_size, const u8 hash[Crypto::kSha256HashLen])
{
	exefs_.size = size;
	exefs_.hashed_size = hashed_data_size;
	memcpy(exefs_.hash, hash, Crypto::kSha256HashLen);
}

void NcchHeader::SetRomfsData(u32 size, u32 hashed_data_size, const u8 hash[Crypto::kSha256HashLen])
{
	romfs_.size = size;
	romfs_.hashed_size = hashed_data_size;
	memcpy(romfs_.hash, hash, Crypto::kSha256HashLen);
}

void NcchHeader::DeserialiseHeader(const u8* ncch_data)
{
	// allocate and save a copy of serialised data
	if (serialised_data_.alloc(sizeof(sSignedNcchHeader))) 
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for NCCH header");
	}

	memcpy(serialised_data_.data(), ncch_data, serialised_data_.size());

	const sSignedNcchHeader* hdr = (const sSignedNcchHeader*)(serialised_data_.data_const());

	if (memcmp(hdr->body.struct_signature(), kNcchStructSignature, 4) != 0)
	{
		throw ProjectSnakeException(kModuleName, "NCCH header is corrupt");
	}

	// determine format version
	format_version_ = hdr->body.format_version();
	if (format_version_ == 0 || format_version_ == 2)
	{
		block_size_bit_ = hdr->body.block_size() + 9;
		block_size_ = 1 << block_size_bit_;
	}
	else if (format_version_ == 1)
	{
		block_size_ = hdr->body.block_size();
	}

	
	ncch_binary_size_ = BlockNumToSize(hdr->body.size());
	title_id_ = hdr->body.title_id();
	company_code_ = std::string(hdr->body.company_code(), kCompanyCodeLen);
	seed_checksum_ = hdr->body.seed_checksum();
	program_id_ = hdr->body.program_id();
	logo_.set_hash(hdr->body.logo_hash());
	product_code_ = std::string(hdr->body.product_code(), kProductCodeLen);
	exheader_.set_hash(hdr->body.exheader_hash());
	exheader_.size = hdr->body.exheader_size();
	key_id_ = hdr->body.key_id();
	platform_ = hdr->body.platform();
	form_type_ = hdr->body.form_type();
	content_type_ = hdr->body.content_type();
	is_encrypted_ = !hdr->body.other_flag_bit(NO_AES);
	is_manual_disclosed_ = hdr->body.other_flag_bit(MANUAL_DISCLOSURE);
	is_fixed_aes_key_ = hdr->body.other_flag_bit(FIXED_AES_KEY);
	is_seeded_keyy_ = hdr->body.other_flag_bit(SEED_KEY);
	plain_region_.size = BlockNumToSize(hdr->body.plain_region().size());
	plain_region_.offset = BlockNumToSize(hdr->body.plain_region().offset());
	logo_.size = BlockNumToSize(hdr->body.logo().size());
	logo_.offset = BlockNumToSize(hdr->body.logo().offset());
	exefs_.size = BlockNumToSize(hdr->body.exefs().size());
	exefs_.offset = BlockNumToSize(hdr->body.exefs().offset());
	exefs_.hashed_size = BlockNumToSize(hdr->body.exefs().hashed_size());
	exefs_.set_hash(hdr->body.exefs_hash());
	romfs_.size = BlockNumToSize(hdr->body.romfs().size());
	romfs_.offset = BlockNumToSize(hdr->body.romfs().offset());
	romfs_.hashed_size = BlockNumToSize(hdr->body.romfs().hashed_size());
	romfs_.set_hash(hdr->body.romfs_hash());
}

bool NcchHeader::ValidateSignature(const Crypto::sRsa2048Key & ncch_rsa_key) const
{
	const struct sSignedNcchHeader* data = (const struct sSignedNcchHeader*)serialised_data_.data_const();

	// hash header
	u8 hash[Crypto::kSha256HashLen];
	Crypto::Sha256((const u8*)&data->body, sizeof(sNcchHeader), hash);

	// verify signature	
	return Crypto::RsaVerify(ncch_rsa_key, Crypto::HASH_SHA256, hash, data->rsa_signature) == 0;
}

bool NcchHeader::ValidatePreloadSeed(const u8 seed[Crypto::kAes128KeySize])
{
	if (!HasPreloadSeed())
	{
		return false;
	}

	
	struct sSeedValidateStruct seed_validate;

	seed_validate.set_seed(seed);
	seed_validate.set_program_id(GetProgramId());


	return GetSeedChecksum() == seed_validate.seed_checksum();
}

u64 NcchHeader::GetNcchSize() const
{
	return ncch_binary_size_;
}

u64 NcchHeader::GetTitleId() const
{
	return title_id_;
}

const std::string & NcchHeader::GetCompanyCode() const
{
	return company_code_;
}

u16 NcchHeader::GetFormatVersion() const
{
	return format_version_;
}

u32 NcchHeader::GetSeedChecksum() const
{
	return seed_checksum_;
}

u64 NcchHeader::GetProgramId() const
{
	return program_id_;
}

const u8 * NcchHeader::GetLogoHash() const
{
	return logo_.hash;
}

const std::string & NcchHeader::GetProductCode() const
{
	return product_code_;
}

const u8 * NcchHeader::GetExheaderHash() const
{
	return exheader_.hash;
}

u32 NcchHeader::GetExheaderSize() const
{
	return exheader_.size;
}

u8 NcchHeader::GetKeyId() const
{
	return key_id_;
}

NcchHeader::Platform NcchHeader::GetPlatform() const
{
	return platform_;
}

NcchHeader::FormType NcchHeader::GetFormType() const
{
	return form_type_;
}

NcchHeader::ContentType NcchHeader::GetContentType() const
{
	return content_type_;
}

u32 NcchHeader::GetBlockSize() const
{
	return block_size_;
}

bool NcchHeader::IsEncrypted() const
{
	return is_encrypted_;
}

bool NcchHeader::IsFixedAesKey() const
{
	return is_fixed_aes_key_;
}

bool NcchHeader::HasPreloadSeed() const
{
	return is_seeded_keyy_;
}

bool NcchHeader::IsPreloadManualDisclosed() const
{
	return is_manual_disclosed_;
}

u64 NcchHeader::GetPlainRegionOffset() const
{
	return plain_region_.offset;
}

u64 NcchHeader::GetPlainRegionSize() const
{
	return plain_region_.size;
}

u64 NcchHeader::GetLogoOffset() const
{
	return logo_.offset;
}

u64 NcchHeader::GetLogoSize() const
{
	return logo_.size;
}

u64 NcchHeader::GetExefsOffset() const
{
	return exefs_.offset;
}

u64 NcchHeader::GetExefsSize() const
{
	return exefs_.size;
}

u64 NcchHeader::GetExefsHashedRegionSize() const
{
	return exefs_.hashed_size;
}

u64 NcchHeader::GetRomfsOffset() const
{
	return romfs_.offset;
}

u64 NcchHeader::GetRomfsSize() const
{
	return romfs_.size;
}

u64 NcchHeader::GetRomfsHashedRegionSize() const
{
	return romfs_.hashed_size;
}

const u8 * NcchHeader::GetExefsHash() const
{
	return exefs_.hash;
}

const u8 * NcchHeader::GetRomfsHash() const
{
	return romfs_.hash;
}

void NcchHeader::FinaliseNcchLayout()
{
	u32 size = Crypto::kRsa2048Size + sizeof(struct sNcchHeader);
	
	// exheader
	if (exheader_.size)
	{
		size += align(exheader_.size, block_size_) + align(access_descriptor_.size, block_size_);
	}

	// logo
	if (logo_.size)
	{
		logo_.offset = size;
		size += align(logo_.size, block_size_);
	}

	// plain region
	if (plain_region_.size)
	{
		plain_region_.offset = size;
		size += align(plain_region_.size, block_size_);
	}

	// exefs
	if (exefs_.size)
	{
		exefs_.offset = size;
		size += align(exefs_.size, block_size_);
	}

	// romfs
	if (romfs_.size)
	{
		romfs_.offset = size;
		size += align(romfs_.size, block_size_);
	}

	ncch_binary_size_ = size;
}

u32 NcchHeader::SizeToBlockNum(u64 size)
{
	u32 block_num = 0;
	if (format_version_ == 0 || format_version_ == 2) 
	{
		block_num = (u32)(align(size, block_size_) >> block_size_bit_);
	}
	else if (format_version_ == 1)
	{
		block_num = (u32)(align(size, block_size_) / block_size_);
	}
	return block_num;
}

u64 NcchHeader::BlockNumToSize(u32 block_num)
{
	u64 size = 0;
	if (format_version_ == 0 || format_version_ == 2)
	{
		size = ((u64)block_num) << block_size_bit_;
	}
	else if (format_version_ == 1)
	{
		size = block_num * block_size_;
	}
	return size;
}
