#pragma once
#include "types.h"
#include "crypto.h"
#include "es_crypto.h"
#include "es_cert.h"
#include "YamlFile.h"

#include <vector>

/*
TODO:
 Add proper error codes
 Add proper sanity checks and error handling
*/

class KeyStore
{
public:
	enum ErrorCode
	{
		ERR_NOERROR,
		ERR_FAILED_TO_PARSE_KSF,
		ERR_KSF_ELEMENT_NOT_PRESENT,
		ERR_DATA_NOT_EXIST,
		ERR_DATA_ALREADY_EXIST,
		ERR_DATA_CORRUPT,
	};

	enum FixedKeyId
	{
		APP_FIXED_KEY,
		SYSTEM_FIXED_KEY
	};

	enum EsIdentType
	{
		IDENT_ROOT, // Root
		IDENT_CA, // Certificate Authority
		IDENT_XS, // Ticket
		IDENT_CP, // Tmd
	};

	enum CtrRsaKeyId
	{
		CTR_NCSD_CFA,
		CTR_ACCESSDESC,
		CTR_FIRM,
		CTR_CRR,
		CTR_SECURE_INFO,
		CTR_MOVEABLE_SEED,
	};

	KeyStore();
	~KeyStore();

	int ParseKeySpecFile(const char* path);

	
	int GetEsCert(EsIdentType id, EsCert& cert);
	int GetEsRsa2048Key(EsIdentType id, Crypto::sRsa2048Key& rsa_key);
	int GetCommonKey(u8 index, u8* aes_key);
	
	int GetCtrRsa2048Key(CtrRsaKeyId id, Crypto::sRsa2048Key& rsa_key);
	int GetFixedKey(FixedKeyId id, u8* aes_key);
	int GetUnfixedKey(u8 index, u8* aes_key_x);


private:
	// generic aes key strings
	const std::string kIdStr = "Id";
	const std::string kAesKeyStr = "AesKey";
	const std::string kAesKeyXStr = "AesSeedX";
	const std::string kAesKeyYStr = "AesSeedY";

	// generic rsa key strings
	const std::string kModulusStr = "N";
	const std::string kPrivateExponentStr = "D";

	// es keys
	const std::string kEsNodeStr = "EsPki";
	const std::string kRootKeyStr = "RootKey";
	const std::string kCaKeyStr = "CaKey";
	const std::string kCaCertStr = "CaCert";
	const std::string kXsKeyStr = "TikKey";
	const std::string kXsCertStr = "TikCert";
	const std::string kCpKeyStr = "TmdKey";
	const std::string kCpCertStr = "TmdCert";
	const std::string kCommonKeyStr = "CommonKey";

	// ctr keys
	const std::string kCtrNodeStr = "Ctr";
	const std::string kNcsdCfaStr = "NcsdCfaKey";
	const std::string kAccessDescStr = "AccessDescriptorKey";
	const std::string kCrrStr = "CrrKey";
	const std::string kAppFixedKeyStr = "AppFixedKey";
	const std::string kSysFixedKeyStr = "SystemFixedKey";
	const std::string kUnfixedKeyStr = "UnfixedKey";
	

	struct sRsa2048Key
	{
		u8 id;
		Crypto::sRsa2048Key key;
	};

	struct sEsCertificate
	{
		u8 id;
		EsCert certificate;
	};

	struct sAesKey
	{
		u8 id;
		u8 key[Crypto::kAes128KeySize];
	};

	struct sEsPki 
	{
		std::vector<sEsCertificate> certifcates;
		std::vector<sRsa2048Key> rsa_keys;
		std::vector<sAesKey> common_keys;
	} es_;

	struct sCtr 
	{
		std::vector<sRsa2048Key> rsa_keys;
		std::vector<sAesKey> fixed_keys;
		std::vector<sAesKey> unfixed_keys;
	} ctr_;

	YamlFile yaml_;

	int SaveEsRsaKeys();
	int SaveEsCertificates();
	int SaveCommonKeys();
	
	int SaveCtrRsaKeys();
	int SaveFixedKeys();
	int SaveUnfixedKeys();
	

	int SaveCommonKey(const YamlElement* node);
	int SaveUnfixedKey(const YamlElement* node);
	int SaveRsa2048Key(const YamlElement* node, Crypto::sRsa2048Key& rsa_key);
	int SaveEsCertificate(const YamlElement* node, EsCert& certificate);


	int AddAesKey(u8 id, const u8* key, std::vector<sAesKey>& key_list);
	int GetAesKey(const std::vector<sAesKey>& key_list, u8 id, u8* key_output);
	int AddRsa2048Key(u8 id, const Crypto::sRsa2048Key& key, std::vector<sRsa2048Key>& key_list);
	int GetRsa2048Key(const std::vector<sRsa2048Key>& key_list, u8 id, Crypto::sRsa2048Key& key_output);
	int AddEsCertificate(u8 id, const EsCert& certificate, std::vector<sEsCertificate>& cert_list);
	int GetEsCertificate(const std::vector<sEsCertificate>& cert_list, u8 id, EsCert& cert_output);

	int DecodeHexString(const std::string& hex_str, size_t len, u8 *out);

	void SetUpYamlLayout(void);
};
