#pragma once
#include "types.h"
#include "crypto.h"
#include "es_crypto.h"
#include "es_cert.h"
#include "YamlFile.h"

#include <vector>


class KeyStore
{
public:
	KeyStore();
	~KeyStore();

	int ParseKeySpecFile(const char* path);

private:
	enum FixedKeyId {
		APP_FIXED_KEY,
		SYSTEM_FIXED_KEY
	};

	struct sCommonKey {
		u8 index;
		u8 key[Crypto::kAes128KeySize];
	};

	struct sFixedNcchKey {
		FixedKeyId id;
		u8 key[Crypto::kAes128KeySize];
	};

	struct sUnfixedNcchKey {
		u8 key_id;
		u8 key_x[Crypto::kAes128KeySize];
	};

	struct sEsPki {
		EsCert ca_cert;

		EsCert tik_cert;
		Crypto::sRsa2048Key tik_key;
		
		EsCert tmd_cert;
		Crypto::sRsa2048Key tmd_key;

		std::vector<sCommonKey> common_keys;
	} es_;

	struct sCtr {
		Crypto::sRsa2048Key ncsd_cfa_key;
		Crypto::sRsa2048Key access_descriptor_key;
		Crypto::sRsa2048Key crr_key;

		std::vector<sFixedNcchKey> fixed_keys;
		std::vector<sUnfixedNcchKey> unfixed_keys;
	} ctr_;

	YamlFile yaml_;

	void SetUpYamlLayout(void);
};
