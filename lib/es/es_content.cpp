#include "es_content.h"

ESContent::ESContent(const ESContentInfo& info, const u8 * data)
	: ESContentInfo(info)
{
	SetLegacy(false);
	is_shallow_copy_ = true;
	data_ptr_ = data;
}

ESContent::ESContent(const ESContentInfo & info, const u8 * data, bool isLegacy) 
	: ESContentInfo(info)
{
	SetLegacy(isLegacy);
	is_shallow_copy_ = true;
	data_ptr_ = data;
}


ESContent::~ESContent()
{
}

void ESContent::EnableContent(bool isEnabled)
{
	is_content_enabled_ = isEnabled;
}

const u8 * ESContent::GetData() const
{
	return is_shallow_copy_? data_ptr_ : content_.data();
}

bool ESContent::IsContentEnabled() const
{
	return is_content_enabled_;
}

void ESContent::SetupAesIV(u8 iv[Crypto::kAesBlockSize]) const
{
	ESCrypto::SetupContentAesIv(GetContentIndex(), iv);
}

void ESContent::EncryptContent(const u8 key[Crypto::kAes128KeySize])
{
	// init vector
	u8 iv[Crypto::kAesBlockSize];
	SetupAesIV(iv);

	// if this is a shallow copy
	// allocate and send decrypted data to the allocation
	if (is_shallow_copy_ == true)
	{
		content_.alloc(GetSize());
		Crypto::AesCbcEncrypt(data_ptr_, GetSize(), key, iv, content_.data());
		is_shallow_copy_ = false;
		data_ptr_ = nullptr;
	}
	// otherwise overwrite the existing data
	else
	{
		Crypto::AesCbcEncrypt(content_.data(), GetSize(), key, iv, content_.data());
	}
}

void ESContent::DecryptContent(const u8 key[Crypto::kAes128KeySize])
{
	// init vector
	u8 iv[Crypto::kAesBlockSize];
	SetupAesIV(iv);

	// if this is a shallow copy
	// allocate and send decrypted data to the allocation
	if (is_shallow_copy_ == true)
	{
		content_.alloc(GetSize());
		Crypto::AesCbcDecrypt(data_ptr_, GetSize(), key, iv, content_.data());
		is_shallow_copy_ = false;
		data_ptr_ = nullptr;
	}
	// otherwise overwrite the existing data
	else
	{
		Crypto::AesCbcDecrypt(content_.data(), GetSize(), key, iv, content_.data());
	}
}

bool ESContent::ValidateContentHash() const
{
	u8 hash[Crypto::kSha256HashLen];
	if (IsSha1Hash())
	{
		Crypto::Sha1(GetData(), GetSize(), hash);
	}
	else
	{
		Crypto::Sha256(GetData(), GetSize(), hash);
	}

	return ValidateHash(hash);
}

void ESContent::UpdateContentHash()
{
	u8 hash[Crypto::kSha256HashLen];
	if (IsSha1Hash())
	{
		Crypto::Sha1(GetData(), GetSize(), hash);
		SetHash(hash, true);
	}
	else
	{
		Crypto::Sha256(GetData(), GetSize(), hash);
		SetHash(hash, false);
	}
}

void ESContent::CopyToInternalBuffer()
{
	content_.alloc(GetSize());
	memcpy(content_.data(), data_ptr_, content_.size());
	is_shallow_copy_ = false;
	data_ptr_ = nullptr;
}