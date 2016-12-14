#pragma once
#include "es_content_info.h"
class ESContent : public ESContentInfo
{
public:
	ESContent(const ESContentInfo& info, const u8* data);
	ESContent(const ESContentInfo& info, const u8* data, bool isLegacy);
	~ESContent();

	// get access to data
	const u8* GetData() const;

	// ticket enabled?
	void EnableContent(bool isEnabled);
	bool IsContentEnabled() const;

	// encryption
	void SetupAesIV(u8 iv[Crypto::kAesBlockSize]) const;
	void EncryptContent(const u8 key[Crypto::kAes128KeySize]);
	void DecryptContent(const u8 key[Crypto::kAes128KeySize]);

	// hash related
	void UpdateContentHash();
	bool ValidateContentHash() const;
private:
	bool is_content_enabled_;

	bool is_shallow_copy_;
	const u8* data_ptr_;
	ByteBuffer content_;

	void CopyToInternalBuffer();
};

