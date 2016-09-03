#include "cia_reader.h"



CiaReader::CiaReader()
{
}


CiaReader::~CiaReader()
{
}

void CiaReader::ImportCia(const u8 * cia_data)
{
	// get header
	header_.DeserialiseHeader(cia_data);

	if (header_.GetContentSize() == 0)
	{
		throw ProjectSnakeException(kModuleName, "Cia has no content");
	}

	// get sections
	if (header_.GetCertificateChainSize() > 0)
	{
		certs_.DeserialiseCertChain(cia_data + header_.GetCertificateChainOffset(), header_.GetCertificateChainSize());
	}

	if (header_.GetTicketSize() > 0)
	{
		tik_.DeserialiseTicket(cia_data + header_.GetTicketOffset());
	}

	if (header_.GetTmdSize() > 0)
	{
		tmd_.DeserialiseTmd(cia_data + header_.GetTmdOffset());
	}

	if (header_.GetCxiMetaDataSize() > 0)
	{
		meta_data_.DeserialiseMetaData(cia_data + header_.GetCxiMetaDataOffset(), header_.GetCxiMetaDataSize());
	}

	// corruption check
	if (tmd_.GetTitleId() != tik_.GetTitleId())
	{
		throw ProjectSnakeException(kModuleName, "Cia is corrupt, ticket and tmd has mismatching title ids");
	}

	// save info about
	size_t content_pos = 0;
	for (const auto& tmd_content : tmd_.GetContentList())
	{
		sContentInfo content;
		memset(&content, 0, sizeof(sContentInfo));

		// save pointer
		content.data = cia_data + header_.GetContentOffset() + content_pos;

		// copy tmd data
		content.id = tmd_content.id;
		content.index = tmd_content.index;
		content.flags = tmd_content.flags;
		content.size = tmd_content.size;
		memcpy(content.hash, tmd_content.hash, (content.flags & EsTmd::ES_CONTENT_TYPE_SHA1_HASH) == 0 ? Crypto::kSha256HashLen : Crypto::kSha1HashLen);
		
		// note related data
		content.is_cia_enabled = header_.IsContentEnabled(content.index);
		content.is_tik_enabled = tik_.IsContentEnabled(content.index);

		// add to list
		content_list_.push_back(content);

		// increment pos
		content_pos += align(content.size, 0x10);
	}
}

u64 CiaReader::GetTitleId() const
{
	return tmd_.GetTitleId();
}

u16 CiaReader::GetTitleVersion() const
{
	return tmd_.GetTitleVersion();
}

u8 CiaReader::GetCommonKeyIndex() const
{
	return tik_.GetCommonKeyIndex();
}

void CiaReader::SetCommonKey(const u8 common_key[Crypto::kAes128KeySize])
{
	SetTitleKey(tik_.GetTitleKey(common_key));
}

void CiaReader::SetTitleKey(const u8 title_key[Crypto::kAes128KeySize])
{
	memcpy(title_key_, title_key, Crypto::kAes128KeySize);
}

const EsCertChain & CiaReader::GetCertificateChain() const
{
	return certs_;
}

const EsTicket & CiaReader::GetTicket() const
{
	return tik_;
}

const EsTmd & CiaReader::GetTmd() const
{
	return tmd_;
}

const CiaCxiMetaData & CiaReader::GetCxiMetaData() const
{
	return meta_data_;
}

const std::vector<CiaReader::sContentInfo>& CiaReader::GetContentList() const
{
	return content_list_;
}

void CiaReader::DecryptContentToBuffer(const sContentInfo & content, ByteBuffer & out)
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

bool CiaReader::VerifyContent(const sContentInfo& content)
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

	if (EsTmd::IsSha1Hash(content.flags))
	{
		u8 hash[Crypto::kSha1HashLen];
		Crypto::Sha1(data, content.size, hash);
		hash_valid = memcmp(hash, content.hash, Crypto::kSha1HashLen) == 0;
	}
	else
	{
		u8 hash[Crypto::kSha256HashLen];
		Crypto::Sha256(data, content.size, hash);
		hash_valid = memcmp(hash, content.hash, Crypto::kSha256HashLen) == 0;
	}

	return hash_valid;
}

bool CiaReader::ValidateCertificates(const Crypto::sRsa4096Key & root_key) const
{
	return certs_.ValidateChain(root_key);
}

bool CiaReader::ValidateCertificatesExceptCa() const
{
	return certs_.ValidateChainExceptCa();
}

bool CiaReader::ValidateTicket() const
{
	return tik_.ValidateSignature(certs_[tik_.GetIssuer()]);
}

bool CiaReader::ValidateTmd() const
{
	return tmd_.ValidateSignature(certs_[tmd_.GetIssuer()]);
}
