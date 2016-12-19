#pragma once
#include <fnd/ByteBuffer.h>
#include <es/es_crypto.h>

class ESCert
{
public:
	enum PublicKeyType
	{
		RSA_4096,
		RSA_2048,
		ECDSA,
	};

	ESCert();
	~ESCert();

	void operator=(const ESCert& other);

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Cert Serialisation
	void SerialiseCert(const Crypto::sRsa2048Key& private_key);
	void SerialiseCert(const Crypto::sRsa2048Key& private_key, bool use_sha1);
	void SerialiseCert(const Crypto::sRsa4096Key& private_key);
	void SerialiseCert(const Crypto::sRsa4096Key& private_key, bool use_sha1);
	void SetIssuer(const std::string& issuer);
	void SetName(const std::string& name);
	void SetUniqueId(u32 id);
	void SetPublicKey(const Crypto::sRsa4096Key& key);
	void SetPublicKey(const Crypto::sRsa2048Key& key);
	void SetPublicKey(const Crypto::sEccPoint& key);

	// Cert Deserialisation
	void DeserialiseCert(const u8* cert_data);
	bool ValidateSignature(const Crypto::sRsa2048Key& key) const;
	bool ValidateSignature(const Crypto::sRsa4096Key& key) const;
	bool ValidateSignature(const ESCert& signer) const;
	const std::string& GetIssuer() const;
	const std::string& GetName() const;
	const std::string& GetChildIssuer() const;
	u32 GetUniqueId() const;
	PublicKeyType GetPublicKeyType() const;
	void GetPublicKey(Crypto::sRsa4096Key& key) const;
	void GetPublicKey(Crypto::sRsa2048Key& key) const;
	void GetPublicKey(Crypto::sEccPoint& key) const;

private:
	const std::string kModuleName = "ES_CERT";
	static const size_t kMaxSerialisedData = 0x2000;
	static const int kPublicKeyBufferLen = 0x500;
	static const int kStringMax = ESCrypto::kSignedStringMaxLen;

	// Private Structures
#pragma pack (push, 1)
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
		u8 public_exponent[Crypto::kRsaPublicExponentSize];
		u8 padding[0x34];
	};

	struct sRsa2048PublicKeyBody
	{
		u8 modulus[Crypto::kRsa2048Size];
		u8 public_exponent[Crypto::kRsaPublicExponentSize];
		u8 padding[0x34];
	};

	struct sEcdsaPublicKeyBody
	{
		u8 public_key[Crypto::kEcdsaSize];
		u8 padding[0x3C];
	};
#pragma pack (pop)

	// serialised data
	ByteBuffer serialised_data_;

	// serialised data staging ground
	sCertificateBody cert_body_;

	// serialised data get interface
	inline const char* signature_issuer() const { return cert_body_.issuer; }
	inline PublicKeyType public_key_type() const { return (PublicKeyType)be_word(cert_body_.key_type); }
	inline const char* name() const { return cert_body_.name; }
	inline u32 unique_id() const { return be_word(cert_body_.unique_id); }
	inline const u8* rsa_public_key_modulus(const sRsa4096PublicKeyBody& rsa_key) const { return rsa_key.modulus; }
	inline const u8* rsa_public_key_public_exponent(const sRsa4096PublicKeyBody& rsa_key) const { return rsa_key.public_exponent; }
	inline const u8* rsa_public_key_modulus(const sRsa2048PublicKeyBody& rsa_key) const { return rsa_key.modulus; }
	inline const u8* rsa_public_key_public_exponent(const sRsa2048PublicKeyBody& rsa_key) const { return rsa_key.public_exponent; }
	inline const u8* ecdsa_public_key(const sEcdsaPublicKeyBody& ecdsa_key) const { return ecdsa_key.public_key; }

	// serialised data set interface
	inline void set_signature_issuer(const char* issuer, int len) { memcpy(cert_body_.name, issuer, len < kStringMax ? len : kStringMax); }
	inline void set_public_key_type(PublicKeyType public_key_type) { cert_body_.key_type = be_word(public_key_type); }
	inline void set_name(const char* name, int len) { memcpy(cert_body_.name, name, len < kStringMax? len : kStringMax); }
	inline void set_unique_id(u32 unique_id) { cert_body_.unique_id = be_word(unique_id); }
	inline void set_rsa_public_key_modulus(sRsa4096PublicKeyBody& rsa_key, const u8 modulus[Crypto::kRsa4096Size]) { memcpy(rsa_key.modulus, modulus, Crypto::kRsa4096Size); }
	inline void set_rsa_public_key_public_exponent(sRsa4096PublicKeyBody& rsa_key, const u8 public_exponent[Crypto::kRsaPublicExponentSize]) { memcpy(rsa_key.public_exponent, public_exponent, Crypto::kRsaPublicExponentSize); }
	inline void set_rsa_public_key_modulus(sRsa2048PublicKeyBody& rsa_key, const u8 modulus[Crypto::kRsa4096Size]) { memcpy(rsa_key.modulus, modulus, Crypto::kRsa4096Size); }
	inline void set_rsa_public_key_public_exponent(sRsa2048PublicKeyBody& rsa_key, const u8 public_exponent[Crypto::kRsaPublicExponentSize]) { memcpy(rsa_key.public_exponent, public_exponent, Crypto::kRsaPublicExponentSize); }
	inline void set_ecdsa_public_key(sEcdsaPublicKeyBody& ecdsa_key, const u8 data[Crypto::kEcdsaSize]) { memcpy(ecdsa_key.public_key, data, Crypto::kEcdsaSize); }

	// members for deserialised data
	std::string issuer_;
	std::string name_;
	u32 unique_id_;
	PublicKeyType public_key_type_;
	u8 public_key_[kPublicKeyBufferLen];

	std::string child_issuer_;

	// Deserialisation methods
	void ClearDeserialisedVariables();
	void CreateChildIssuer();
	void HashSerialisedData(ESCrypto::ESSignType type, u8* hash) const;
	void SerialiseWithoutSign(ESCrypto::ESSignType type);

	// utils
	bool IsValidPublicKeyType(PublicKeyType type) const;
	u32 GetPublicKeySize(PublicKeyType type) const;
};

