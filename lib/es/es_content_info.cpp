#include "es_content_info.h"



ESContentInfo::ESContentInfo() :
	cid_(0),
	cidx_(0),
	flags_(0),
	size_(0),
	is_legacy_content_info_(false)
{
	memset(hash_, 0, Crypto::kSha256HashLen);
}

ESContentInfo::ESContentInfo(u32 cid, u16 cidx, u16 flags, u64 size, const u8 * hash) :
	cid_(cid),
	cidx_(cidx),
	flags_(flags),
	size_(size),
	is_legacy_content_info_(false)
{
	SetHash(hash, IsSha1Hash());
}

ESContentInfo::ESContentInfo(u32 cid, u16 cidx, u16 flags, u64 size, const u8 * hash, bool isLegacy) :
	cid_(cid),
	cidx_(cidx),
	flags_(flags),
	size_(size),
	is_legacy_content_info_(isLegacy)
{
	SetHash(hash, IsSha1Hash());
}

ESContentInfo::ESContentInfo(const ESContentInfo & other) :
	cid_(other.GetContentId()),
	cidx_(other.GetContentIndex()),
	flags_(other.GetFlags()),
	size_(other.GetSize()),
	is_legacy_content_info_(other.IsLegacy())
{
	SetHash(other.GetHash(), IsSha1Hash());
}


ESContentInfo::~ESContentInfo()
{
}

void ESContentInfo::SetContentId(u32 cid)
{
	cid_ = cid;
}

void ESContentInfo::SetContentIndex(u16 cidx)
{
	cidx_ = cidx;
}

void ESContentInfo::SetFlags(u32 flags)
{
	flags_ = flags;
}

void ESContentInfo::SetSize(u64 size)
{
	size_ = size;
}

void ESContentInfo::SetHash(const u8 * hash, bool is_sha1)
{
	if (hash == nullptr)
	{
		return;
	}

	memset(hash_, 0, Crypto::kSha256HashLen);
	memcpy(hash_, hash, is_sha1 ? Crypto::kSha1HashLen : Crypto::kSha256HashLen);
}

void ESContentInfo::SetLegacy(bool isLegacy)
{
	is_legacy_content_info_ = isLegacy;
}

u32 ESContentInfo::GetContentId() const
{
	return cid_;
}

u16 ESContentInfo::GetContentIndex() const
{
	return cidx_;
}

u16 ESContentInfo::GetFlags() const
{
	return flags_;
}

u64 ESContentInfo::GetSize() const
{
	return size_;
}

const u8 * ESContentInfo::GetHash() const
{
	return hash_;
}

bool ESContentInfo::ValidateHash(const u8 * hash) const
{
	return memcmp(hash_, hash, IsSha1Hash()? Crypto::kSha1HashLen : Crypto::kSha256HashLen) == 0;
}

bool ESContentInfo::IsFlagSet(ESContentFlag flag) const
{
	return (flags_ & flag) == flag;
}

bool ESContentInfo::IsLegacy() const
{
	return is_legacy_content_info_;
}

bool ESContentInfo::IsSha1Hash() const
{
	return IsFlagSet(ESContentFlag::ES_CONTENT_FLAG_SHA1_HASH) || IsLegacy();
}