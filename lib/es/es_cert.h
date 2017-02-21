#pragma once
#include <fnd/memory_blob.h>
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
	void SetSubject(const std::string& name);
	void SetUniqueId(u32 id);
	void SetPublicKey(const Crypto::sRsa4096Key& key);
	void SetPublicKey(const Crypto::sRsa2048Key& key);
	void SetPublicKey(const Crypto::sEccPoint& key);

	// Cert Deserialisation
	void DeserialiseCert(const u8* cert_data);
	bool ValidateSignature(const Crypto::sRsa2048Key& key) const;
	bool ValidateSignature(const Crypto::sRsa4096Key& key) const;
	bool ValidateSignature(const ESCert& signer) const;
	ESCrypto::ESSignType GetSignType() const;
	const u8* GetSignature() const;
	size_t GetSignatureSize() const;
	const std::string& GetIssuer() const;
	const std::string& GetSubject() const;
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
	private:
		char issuer_[kStringMax];
		u32 key_type_;
		char subject_[kStringMax];
		u32 unique_id_;
	public:
		inline const char* signature_issuer() const { return issuer_; }
		inline PublicKeyType public_key_type() const { return (PublicKeyType)be_word(key_type_); }
		inline const char* subject() const { return subject_; }
		inline u32 unique_id() const { return be_word(unique_id_); }

		void clear() { memset(this, 0, sizeof(*this)); }

		inline void set_signature_issuer(const char* issuer) { strncpy(issuer_, issuer, kStringMax); }
		inline void set_public_key_type(PublicKeyType public_key_type) { key_type_ = be_word(public_key_type); }
		inline void set_subject(const char* name) { strncpy(subject_, name, kStringMax); }
		inline void set_unique_id(u32 unique_id) { unique_id_ = be_word(unique_id); }
	};

	struct sRsa4096PublicKeyBody
	{
		u8 modulus[Crypto::kRsa4096Size];
		u8 public_exponent[Crypto::kRsaPublicExponentSize];
		u8 padding[0x34];

		void set_modulus(const u8 modulus[Crypto::kRsa4096Size]) { memcpy(this->modulus, modulus, Crypto::kRsa4096Size); }
		void set_public_exponent(const u8 public_exponent[Crypto::kRsaPublicExponentSize]) { memcpy(this->public_exponent, public_exponent, Crypto::kRsaPublicExponentSize); }
		void clear() { memset(this, 0, sizeof(*this)); }
	};

	struct sRsa2048PublicKeyBody
	{
		u8 modulus[Crypto::kRsa2048Size];
		u8 public_exponent[Crypto::kRsaPublicExponentSize];
		u8 padding[0x34];

		void set_modulus(const u8 modulus[Crypto::kRsa2048Size]) { memcpy(this->modulus, modulus, Crypto::kRsa2048Size); }
		void set_public_exponent(const u8 public_exponent[Crypto::kRsaPublicExponentSize]) { memcpy(this->public_exponent, public_exponent, Crypto::kRsaPublicExponentSize); }
		void clear() { memset(this, 0, sizeof(*this)); }
	};

	struct sEcdsaPublicKeyBody
	{
		u8 r[Crypto::kEcParam240Bit];
		u8 s[Crypto::kEcParam240Bit];
		u8 padding[0x3C];

		void set_r(const u8 r[Crypto::kEcParam240Bit]) { memcpy(this->r, r, Crypto::kEcParam240Bit); }
		void set_s(const u8 s[Crypto::kEcParam240Bit]) { memcpy(this->s, s, Crypto::kEcParam240Bit); }
		void clear() { memset(this, 0, sizeof(*this)); }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// members for deserialised data
	std::string issuer_;
	std::string subject_;
	u32 unique_id_;
	PublicKeyType public_key_type_;
	sRsa4096PublicKeyBody public_key_rsa4096_;
	sRsa2048PublicKeyBody public_key_rsa2048_;
	sEcdsaPublicKeyBody public_key_ecdsa_;

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

