#include "wad_reader.h"



WadReader::WadReader()
{
}


WadReader::~WadReader()
{
}

void WadReader::ImportWad(const u8 * wad_data)
{
	// get header
	header_.DeserialiseHeader(wad_data);

	if (header_.GetContentSize() == 0)
	{
		throw ProjectSnakeException(kModuleName, "Wad has no content");
	}

	// get sections
	if (header_.GetCertificateChainSize() > 0)
	{
		certs_.DeserialiseCertChain(wad_data + header_.GetCertificateChainOffset(), header_.GetCertificateChainSize());
	}

	if (header_.GetTicketSize() > 0)
	{
		tik_.DeserialiseTicket(wad_data + header_.GetTicketOffset());
	}

	if (header_.GetTmdSize() > 0)
	{
		tmd_.DeserialiseTmd(wad_data + header_.GetTmdOffset());
	}

	if (header_.GetFooterSize() > 0)
	{
		//footer_.DeserialiseFooter(wad_data + header_.GetFooterOffset(), header_.GetFooterSize());
	}

	// corruption check
	if (tmd_.GetTitleId() != tik_.GetTitleId())
	{
		throw ProjectSnakeException(kModuleName, "Wad is corrupt, ticket and tmd have mismatching title ids");
	}

	// save info about
	size_t content_pos = 0;
	for (const auto& tmd_content : tmd_.GetContentList())
	{
		sContentInfo content;
		memset(&content, 0, sizeof(sContentInfo));

		// save pointer
		content.data = wad_data + header_.GetContentOffset() + content_pos;

		// copy tmd data
		content.id = tmd_content.id;
		content.index = tmd_content.index;
		content.flags = tmd_content.flags;
		content.size = tmd_content.size;
		memcpy(content.hash, tmd_content.hash, Crypto::kSha1HashLen);

		// note related data
		content.is_tik_enabled = tik_.IsContentEnabled(content.index);

		// add to list
		content_list_.push_back(content);

		// increment pos
		content_pos += align(content.size, 0x10);
	}
}

u64 WadReader::GetTitleId() const
{
	return tmd_.GetTitleId();
}

u16 WadReader::GetTitleVersion() const
{
	return tmd_.GetTitleVersion();
}

u8 WadReader::GetCommonKeyIndex() const
{
	return tik_.GetCommonKeyIndex();
}

void WadReader::SetCommonKey(const u8 common_key[Crypto::kAes128KeySize])
{
	SetTitleKey(tik_.GetTitleKey(common_key));
}

void WadReader::SetTitleKey(const u8 title_key[Crypto::kAes128KeySize])
{
	memcpy(title_key_, title_key, Crypto::kAes128KeySize);
}

const EsCertChain & WadReader::GetCertificateChain() const
{
	return certs_;
}

const EsTicket & WadReader::GetTicket() const
{
	return tik_;
}

const EsTmd & WadReader::GetTmd() const
{
	return tmd_;
}

const std::vector<WadReader::sContentInfo>& WadReader::GetContentList() const
{
	return content_list_;
}

void WadReader::DecryptContentToBuffer(const sContentInfo & content, ByteBuffer & out)
{
	if (out.alloc(content.size) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for content");
	}

	// decrypt
	u8 iv[Crypto::kAesBlockSize];
	EsCrypto::SetupContentAesIv(content.index, iv);
	Crypto::AesCbcDecrypt(content.data, content.size, title_key_, iv, out.data());
}

bool WadReader::VerifyContent(const sContentInfo & content)
{
	bool hash_valid = false;

	const u8* data = content.data;
	ByteBuffer dec;
	if (EsTmd::IsEncrypted(content.flags))
	{
		DecryptContentToBuffer(content, dec);

		// override pointer
		data = dec.data_const();
	}

	u8 hash[Crypto::kSha1HashLen];
	Crypto::Sha1(data, content.size, hash);
	hash_valid = memcmp(hash, content.hash, Crypto::kSha1HashLen) == 0;

	return hash_valid;
}

bool WadReader::ValidateCertificates(const Crypto::sRsa4096Key & root_key) const
{
	return certs_.ValidateChain(root_key);
}

bool WadReader::ValidateCertificatesExceptCa() const
{
	return certs_.ValidateChainExceptCa();
}

bool WadReader::ValidateTicket() const
{
	return tik_.ValidateSignature(certs_[tik_.GetIssuer()]);
}

bool WadReader::ValidateTmd() const
{
	return tmd_.ValidateSignature(certs_[tmd_.GetIssuer()]);
}
