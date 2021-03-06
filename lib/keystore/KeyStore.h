#pragma once
#include <vector>
#include <fnd/types.h>
//#include <fnd/memory_blob.h>
#include <es/es_crypto.h>
#include <es/es_cert.h>
#include <yaml/YamlFile.h>

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
		CTR_APP_FIXED_KEY,
		CTR_SYSTEM_FIXED_KEY
	};

	enum EsIdentType
	{
		ES_IDENT_ROOT, // Root
		ES_IDENT_CA, // Certificate Authority
		ES_IDENT_XS, // Ticket
		ES_IDENT_CP, // Tmd
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

	
	int GetEsCert(EsIdentType id, ESCert& cert);
	int GetEsRsa2048Key(EsIdentType id, Crypto::sRsa2048Key& rsa_key);
	int GetEsRsa4096Key(EsIdentType id, Crypto::sRsa4096Key& rsa_key);
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
	const std::string kXsKeyStr = "TicketKey";
	const std::string kXsCertStr = "TicketCert";
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
	

	struct sRsa4096Key
	{
		u8 id;
		Crypto::sRsa4096Key key;
	};

	struct sRsa2048Key
	{
		u8 id;
		Crypto::sRsa2048Key key;
	};

	struct sEsCertificate
	{
		u8 id;
		ESCert certificate;
	};

	struct sAesKey
	{
		u8 id;
		u8 key[Crypto::kAes128KeySize];
	};

	struct sEsPki 
	{
		std::vector<sEsCertificate> certifcates;
		std::vector<sRsa4096Key> rsa4096_keys;
		std::vector<sRsa2048Key> rsa2048_keys;
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
	int SaveRsa4096Key(const YamlElement* node, Crypto::sRsa4096Key& rsa_key);
	int SaveEsCertificate(const YamlElement* node, ESCert& certificate);


	int AddAesKey(u8 id, const u8* key, std::vector<sAesKey>& key_list);
	int GetAesKey(const std::vector<sAesKey>& key_list, u8 id, u8* key_output);
	int AddRsa2048Key(u8 id, const Crypto::sRsa2048Key& key, std::vector<sRsa2048Key>& key_list);
	int GetRsa2048Key(const std::vector<sRsa2048Key>& key_list, u8 id, Crypto::sRsa2048Key& key_output);
	int AddRsa4096Key(u8 id, const Crypto::sRsa4096Key& key, std::vector<sRsa4096Key>& key_list);
	int GetRsa4096Key(const std::vector<sRsa4096Key>& key_list, u8 id, Crypto::sRsa4096Key& key_output);
	int AddEsCertificate(u8 id, const ESCert& certificate, std::vector<sEsCertificate>& cert_list);
	int GetEsCertificate(const std::vector<sEsCertificate>& cert_list, u8 id, ESCert& cert_output);

	int DecodeHexString(const std::string& hex_str, size_t len, u8 *out);

	void PrintElementLoadFailure(const std::string& element_name, const std::string& failure_reason);
	void SetUpYamlLayout(void);
};
