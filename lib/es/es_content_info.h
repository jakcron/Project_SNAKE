#pragma once
#include <fnd/memory_blob.h>
#include <es/es_crypto.h>

class ESContentInfo
{
public:
	enum ESContentType
	{
		ES_CONTENT_TYPE_ENCRYPTED = BIT(0),
		ES_CONTENT_TYPE_DISC = BIT(1),
		ES_CONTENT_TYPE_HASHED = BIT(1),
		ES_CONTENT_TYPE_CFM = BIT(3),
		ES_CONTENT_TYPE_SHA1_HASH = BIT(13),
		ES_CONTENT_TYPE_OPTIONAL = BIT(14),
		ES_CONTENT_TYPE_SHARED = BIT(15),
	};

	ESContentInfo(u32 cid, u16 cidx, u16 flags, u64 size, const u8* hash);
	ESContentInfo(u32 cid, u16 cidx, u16 flags, u64 size, const u8* hash, bool is_legacy);
	ESContentInfo(const ESContentInfo& other);
	~ESContentInfo();

	u32 GetContentId() const;
	u16 GetContentIndex() const;
	u16 GetFlags() const;
	u64 GetSize() const;
	const u8* GetHash() const;

	bool ValidateHash(const u8* hash) const;

	bool IsFlagSet(ESContentType flag) const;
	bool IsLegacy() const;
	bool IsSha1Hash() const; // detects legacy override

protected:
	ESContentInfo();
	void SetContentId(u32 cid);
	void SetContentIndex(u16 cidx);
	void SetFlags(u32 flags);
	void SetSize(u64 size);
	void SetHash(const u8* hash, bool is_sha1);
	void SetLegacy(bool isLegacy);

private:
	u32 cid_;
	u16 cidx_;
	u16 flags_;
	u64 size_;
	u8 hash_[Crypto::kSha256HashLen];
	bool is_legacy_content_info_;
};

