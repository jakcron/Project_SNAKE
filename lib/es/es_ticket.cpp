#include "es_ticket.h"
#include "es_crypto.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

EsTicket::EsTicket() :
    limits_used_(0),
	content_mask_(0)
{
	memset(&body_, 0, sizeof(struct sTicketBody));
}

EsTicket::~EsTicket()
{
}

int EsTicket::CreateTicket(const char* signature_issuer, const u8 rsa_modulus[Crypto::kRsa2048Size], const u8 rsa_priv_exponent[Crypto::kRsa2048Size])
{
	strncpy(body_.signature_issuer, signature_issuer, kSignatureIssuerLen);

	body_.format_version = kFormatVersion;
	body_.ca_crl_version = kCaCrlVersion;
	body_.signer_crl_version = kSignerCrlVersion;

	memset(body_.ecdsa_public_key, 0, kEcdsaPublicKeyLen);

	// create content mask header
	struct sContentMaskHeader index_ctrl_hdr;
	index_ctrl_hdr.header_size = be_word(sizeof(struct sContentMaskHeader));
	index_ctrl_hdr.entry_num = be_word(content_mask_.size());
	index_ctrl_hdr.entry_size = be_word(sizeof(struct sContentMaskChunk));
	index_ctrl_hdr.total_entry_size = be_word(content_mask_.size()*sizeof(struct sContentMaskChunk));
	index_ctrl_hdr.total_size = be_word(be_word(index_ctrl_hdr.total_entry_size) + be_word(index_ctrl_hdr.header_size));
	index_ctrl_hdr.unk0 = be_word(0x00010014);
	index_ctrl_hdr.unk1 = be_word(0x00000014);
	index_ctrl_hdr.unk2 = be_word(0x00010014);
	index_ctrl_hdr.unk3 = be_word(0x00000000);
	index_ctrl_hdr.unk4 = be_word(0x00030000);

	// allocate memory for ticket blob
	safe_call(ticket_.alloc(EsCrypto::kRsa2048SignLen + sizeof(sTicketBody) + be_word(index_ctrl_hdr.total_size)));

	// copy data into blob
	memcpy(ticket_.data() + EsCrypto::kRsa2048SignLen, (const u8*)&body_, sizeof(struct sTicketBody));
	memcpy(ticket_.data() + EsCrypto::kRsa2048SignLen + sizeof(struct sTicketBody), (const u8*)&index_ctrl_hdr, sizeof(struct sContentMaskHeader));
	
	struct sContentMaskChunk* index_entries = (struct sContentMaskChunk*)(ticket_.data() + EsCrypto::kRsa2048SignLen + sizeof(struct sTicketBody) + sizeof(struct sContentMaskHeader));
	for (size_t i = 0; i < content_mask_.size(); i++)
	{
		memcpy((u8*)&index_entries[i], (u8*)&content_mask_[i], sizeof(struct sContentMaskChunk));
	}

	// sign ticket
	u8 hash[Crypto::kSha256HashLen];
	Crypto::Sha256(ticket_.data() + EsCrypto::kRsa2048SignLen, ticket_.size() - EsCrypto::kRsa2048SignLen, hash);
	if (EsCrypto::RsaSign(EsCrypto::ES_SIGN_RSA2048_SHA256, hash, rsa_modulus, rsa_priv_exponent, ticket_.data()) != 0)
	{
		fprintf(stderr, "[ERROR] Failed to sign Ticket!\n");
		return 1;
	}

	return 0;
}

void EsTicket::SetTitleKey(const u8 title_key[Crypto::kAes128KeySize], const u8 common_key[Crypto::kAes128KeySize], u8 common_key_index)
{
	u8 enc_title_key[Crypto::kAes128KeySize];
	u8 iv[Crypto::kAesBlockSize] = { 0 };

	for (int i = 0; i < 8; i++)
	{
		iv[i] = (be_dword(body_.title_id) >> (56 - i * 8)) & 0xff;
	}
	Crypto::AesCbcEncrypt(title_key, Crypto::kAes128KeySize, common_key, iv, enc_title_key);
	SetEncryptedTitleKey(enc_title_key, common_key_index);
}

void EsTicket::SetEncryptedTitleKey(const u8 title_key[Crypto::kAes128KeySize], u8 common_key_index)
{
	memcpy(body_.title_key, title_key, Crypto::kAes128KeySize);
	body_.common_key_index = common_key_index;
}

void EsTicket::SetTicketId(u64 ticket_id)
{
	body_.ticket_id = be_dword(ticket_id);
}

void EsTicket::SetConsoleId(u32 console_id)
{
	body_.console_id = be_word(console_id);
}

void EsTicket::SetTitleId(u64 title_id)
{
	body_.title_id = be_dword(title_id);
}

void EsTicket::SetTitleVersion(u16 version)
{
	body_.title_version = be_hword(version);
}

void EsTicket::SetLicenseType(ESLicenseType type)
{
	body_.license_type = type;
}

void EsTicket::SetEshopAccountId(u32 account_id)
{
	body_.eshop_account_id = be_dword(account_id);
}

void EsTicket::SetAudit(u8 audit)
{
	body_.audit = audit;
}

int EsTicket::AddLimit(ESLimitCode id, u32 value)
{
	if (limits_used_ >= kMaxLimitNum) die("[ERROR] Too many ticket limits\n");

	body_.limits[limits_used_].id = be_word(id);
	body_.limits[limits_used_].value = be_word(value);

	limits_used_++;

	return 0;
}

void EsTicket::SetContentMask(const std::vector<u16>& indexes)
{
	struct sContentMaskChunk entry;

	for (size_t i = 0; i < indexes.size(); i++)
	{
		if (entry.index_block != (indexes[i] >> 10))
		{
			if (i > 0)
			{
				content_mask_.push_back(entry);
			}
			ClearContentIndexControlEntry(entry);
			entry.index_block = (indexes[i] >> 10);
		}
		
		entry.num[(indexes[i] % BIT(10)) / sizeof(u8)] |= BIT(indexes[i] % sizeof(u8));
	}
	content_mask_.push_back(entry);
}

void EsTicket::ClearContentIndexControlEntry(sContentMaskChunk & entry)
{
	entry.index_block = 0;
	memset(entry.num, 0, kContentMaskBlockSize);
}
