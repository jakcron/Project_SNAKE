#pragma once
#include <string>
#include "ByteBuffer.h"
#include "es_crypto.h"

class EsCert
{
public:
	enum PublicKeyType
	{
		RSA_4096,
		RSA_2048,
		ECDSA,
	};

	EsCert();
	~EsCert();

	//int CreateCertificate(const char* signature_issuer, const u8 rsa_modulus[Crypto::kRsa2048Size], const u8 rsa_priv_exponent[Crypto::kRsa2048Size]);
	inline const u8* data_blob() const { return blob_.data_const(); }
	inline u32 data_size() const { return blob_.size(); }

	// Import existing certificate
	int ImportCert(const void* cert);

	//int SetIssuer()
	//int SetPublicKey(PublicKeyType type, const u8* public_key);

	// Get components of certificate
	inline const char* issuer() const { return body_.issuer; }
	inline PublicKeyType public_key_type() const { return (PublicKeyType)be_word(body_.key_type); }
	inline const char* name() const { return body_.name; }
	inline u32 unique_id() const { return be_word(body_.unique_id); }
	inline const u8* public_key() const { return public_key_.data_const(); }

	inline const char* chlid_issuer() const { return child_issuer_; }

private:
	static const int kStringMax = EsCrypto::kSignedStringMaxLen;

	struct sCertificateBody
	{
		char issuer[kStringMax];
		u32 key_type;
		char name[kStringMax];
		u32 unique_id;
	};

	struct sRsa4096PublicKeyBody
	{
		u8 modulus[Crypto::kRsa4096Size];
		u8 public_exponent[4];
		u8 padding[0x34];
	};

	struct sRsa2048PublicKeyBody
	{
		u8 modulus[Crypto::kRsa2048Size];
		u8 public_exponent[4];
		u8 padding[0x34];
	};

	struct sEcdsaPublicKeyBody
	{
		u8 public_key[0x3C];
		u8 padding[0x34];
	};

	ByteBuffer blob_;
	sCertificateBody body_;
	ByteBuffer public_key_;

	char child_issuer_[kStringMax];

	u32 GetPublicKeySize(PublicKeyType type);
};
