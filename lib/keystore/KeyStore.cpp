#include "KeyStore.h"

//#define KEYSTORE_DEBUG true

KeyStore::KeyStore()
{
	SetUpYamlLayout();
}

KeyStore::~KeyStore()
{
}

int KeyStore::ParseKeySpecFile(const char* path)
{
	yaml_.ParseFile(path);

	// process es data
	SaveCommonKeys();
	SaveEsRsaKeys();
	SaveEsCertificates();


	// process ctr data
	SaveFixedKeys();
	SaveUnfixedKeys();
	SaveCtrRsaKeys();
	
#ifdef KEYSTORE_DEBUG
	printf("[KEYSTORE DEBUG] IMPORT SUMMARY\n");
	printf("es rsa keys: %d\n", es_.rsa2048_keys.size() + es_.rsa4096_keys.size());
	printf("es common keys: %d\n", es_.common_keys.size());
	printf("es certs: %d\n", es_.certifcates.size());

	printf("ctr rsa keys: %d\n", ctr_.rsa_keys.size());
	printf("ctr fixed keys: %d\n", ctr_.fixed_keys.size());
	printf("ctr unfixed keys: %d\n", ctr_.unfixed_keys.size());
#endif

	return ERR_NOERROR;
}

int KeyStore::GetEsCert(EsIdentType id, ESCert& cert)
{
	return GetEsCertificate(es_.certifcates, id, cert);
}

int KeyStore::GetEsRsa2048Key(EsIdentType id, Crypto::sRsa2048Key & rsa_key)
{
	return GetRsa2048Key(es_.rsa2048_keys, id, rsa_key);
}

int KeyStore::GetEsRsa4096Key(EsIdentType id, Crypto::sRsa4096Key & rsa_key)
{
	return GetRsa4096Key(es_.rsa4096_keys, id, rsa_key);
}

int KeyStore::GetCommonKey(u8 index, u8* aes_key)
{
	return GetAesKey(es_.common_keys, index, aes_key);
}

int KeyStore::GetCtrRsa2048Key(CtrRsaKeyId id, Crypto::sRsa2048Key& rsa_key)
{
	return GetRsa2048Key(ctr_.rsa_keys, id, rsa_key);
}

int KeyStore::GetFixedKey(FixedKeyId id, u8* aes_key)
{
	return  GetAesKey(ctr_.fixed_keys, id, aes_key);
}

int KeyStore::GetUnfixedKey(u8 index, u8* aes_key_x)
{
	return GetAesKey(ctr_.unfixed_keys, index, aes_key_x);
}

int KeyStore::SaveRsa2048Key(const YamlElement* node, Crypto::sRsa2048Key& rsa_key)
{
	const YamlElement *private_exponent, *modulus;

	if (node == nullptr)
	{
		return ERR_KSF_ELEMENT_NOT_PRESENT;
	}

	modulus = node->GetChild(kModulusStr);
	private_exponent = node->GetChild(kPrivateExponentStr);

	if (modulus != nullptr && !modulus->data().empty())
	{
		if (DecodeHexString(modulus->data()[0], Crypto::kRsa2048Size, rsa_key.modulus) != ERR_NOERROR)
		{
			return ERR_DATA_CORRUPT;
		}
	}
	else
	{
		return ERR_KSF_ELEMENT_NOT_PRESENT;
	}

	if (private_exponent != nullptr && !private_exponent->data().empty())
	{
		if (DecodeHexString(private_exponent->data()[0], Crypto::kRsa2048Size, rsa_key.priv_exponent) != ERR_NOERROR)
		{
			return ERR_DATA_CORRUPT;
		}
	}
	else
	{
		memset(rsa_key.priv_exponent, 0, Crypto::kRsa2048Size);
	}

	return ERR_NOERROR;
}

int KeyStore::SaveRsa4096Key(const YamlElement * node, Crypto::sRsa4096Key & rsa_key)
{
	const YamlElement *private_exponent, *modulus;

	if (node == nullptr)
	{
		return ERR_KSF_ELEMENT_NOT_PRESENT;
	}

	modulus = node->GetChild(kModulusStr);
	private_exponent = node->GetChild(kPrivateExponentStr);

	if (modulus != nullptr && !modulus->data().empty())
	{
		if (DecodeHexString(modulus->data()[0], Crypto::kRsa4096Size, rsa_key.modulus) != ERR_NOERROR)
		{
			return ERR_DATA_CORRUPT;
		}
	}
	else
	{
		return ERR_KSF_ELEMENT_NOT_PRESENT;
	}

	if (private_exponent != nullptr && !private_exponent->data().empty())
	{
		if (DecodeHexString(private_exponent->data()[0], Crypto::kRsa4096Size, rsa_key.priv_exponent) != ERR_NOERROR)
		{
			return ERR_DATA_CORRUPT;
		}
	}
	else
	{
		memset(rsa_key.priv_exponent, 0, Crypto::kRsa4096Size);
	}

	return ERR_NOERROR;
}

int KeyStore::SaveEsCertificate(const YamlElement* node, ESCert& certificate)
{
	if (node == nullptr)
	{
		return ERR_KSF_ELEMENT_NOT_PRESENT;
	}

	if (!node->data().empty())
	{
		ByteBuffer tmp;
		tmp.alloc(node->data()[0].size() / 2);
		if (DecodeHexString(node->data()[0], tmp.size(), tmp.data()) != ERR_NOERROR)
		{
			return ERR_DATA_CORRUPT;
		}

		try {
			certificate.DeserialiseCert(tmp.data_const());
		}
		catch (const ProjectSnakeException& error) {
			PrintElementLoadFailure(node->name(), error.what());
			return ERR_DATA_CORRUPT;
		}
		return ERR_NOERROR;
	}

	return ERR_DATA_CORRUPT;
}

int KeyStore::SaveEsRsaKeys()
{
	Crypto::sRsa4096Key rsa4096_key;
	Crypto::sRsa2048Key rsa2048_key;

	if (SaveRsa4096Key(yaml_.GetDataElement(kEsNodeStr + "/" + kRootKeyStr), rsa4096_key) == ERR_NOERROR)
	{
		AddRsa4096Key(ES_IDENT_ROOT, rsa4096_key, es_.rsa4096_keys);
	}
	if (SaveRsa2048Key(yaml_.GetDataElement(kEsNodeStr + "/" + kCaKeyStr), rsa2048_key) == ERR_NOERROR)
	{
		AddRsa2048Key(ES_IDENT_CA, rsa2048_key, es_.rsa2048_keys);
	}
	if (SaveRsa2048Key(yaml_.GetDataElement(kEsNodeStr + "/" + kXsKeyStr), rsa2048_key) == ERR_NOERROR)
	{
		AddRsa2048Key(ES_IDENT_XS, rsa2048_key, es_.rsa2048_keys);
	}
	if (SaveRsa2048Key(yaml_.GetDataElement(kEsNodeStr + "/" + kCpKeyStr), rsa2048_key) == ERR_NOERROR)
	{
		AddRsa2048Key(ES_IDENT_CP, rsa2048_key, es_.rsa2048_keys);
	}

	return ERR_NOERROR;
}

int KeyStore::SaveEsCertificates()
{
	ESCert certificate;
	if (SaveEsCertificate(yaml_.GetDataElement(kEsNodeStr + "/" + kCaCertStr), certificate) == ERR_NOERROR)
	{
		AddEsCertificate(ES_IDENT_CA, certificate, es_.certifcates);
	}
	if (SaveEsCertificate(yaml_.GetDataElement(kEsNodeStr + "/" + kXsCertStr), certificate) == ERR_NOERROR)
	{
		AddEsCertificate(ES_IDENT_XS, certificate, es_.certifcates);
	}
	if (SaveEsCertificate(yaml_.GetDataElement(kEsNodeStr + "/" + kCpCertStr), certificate) == ERR_NOERROR)
	{
		AddEsCertificate(ES_IDENT_CP, certificate, es_.certifcates);
	}

	return ERR_NOERROR;
}

int KeyStore::SaveCommonKeys()
{
	const YamlElement* espki = yaml_.GetDataElement(kEsNodeStr);
	
	if (espki == nullptr)
	{
		return ERR_KSF_ELEMENT_NOT_PRESENT;
	}

	size_t commonkey_num = espki->GetChildOccurence(kCommonKeyStr);
	for (size_t i = 0; i < commonkey_num; i++)
	{
		SaveCommonKey(espki->GetChild(kCommonKeyStr, i));
	}

	return ERR_NOERROR;
}

int KeyStore::SaveCommonKey(const YamlElement* node)
{
	const YamlElement *ksf_index, *ksf_key;
	u8 key_id, aes_key[Crypto::kAes128KeySize];

	if (node == nullptr)
	{
		return 1;
	}

	ksf_index = node->GetChild(kIdStr);
	ksf_key = node->GetChild(kAesKeyStr);

	if (ksf_index != nullptr && !ksf_index->data().empty())
	{
		key_id = strtol(ksf_index->data()[0].c_str(), NULL, 0);
	}

	if (ksf_key != nullptr && !ksf_key->data().empty())
	{
		DecodeHexString(ksf_key->data()[0], Crypto::kAes128KeySize, aes_key);
	}

	AddAesKey(key_id, aes_key, es_.common_keys);

	return 0;
}

int KeyStore::SaveCtrRsaKeys()
{
	Crypto::sRsa2048Key rsa_key;

	if (SaveRsa2048Key(yaml_.GetDataElement(kCtrNodeStr + "/" + kNcsdCfaStr), rsa_key) == ERR_NOERROR)
	{
		AddRsa2048Key(CTR_NCSD_CFA, rsa_key, ctr_.rsa_keys);
	}
	if (SaveRsa2048Key(yaml_.GetDataElement(kCtrNodeStr + "/" + kAccessDescStr), rsa_key) == ERR_NOERROR)
	{
		AddRsa2048Key(CTR_ACCESSDESC, rsa_key, ctr_.rsa_keys);
	}
	if (SaveRsa2048Key(yaml_.GetDataElement(kCtrNodeStr + "/" + kCrrStr), rsa_key) == ERR_NOERROR)
	{
		AddRsa2048Key(CTR_CRR, rsa_key, ctr_.rsa_keys);
	}

	return ERR_NOERROR;
}

int KeyStore::SaveFixedKeys()
{
	const YamlElement* app_fixed = yaml_.GetDataElement(kCtrNodeStr + "/" + kAppFixedKeyStr);
	const YamlElement* sys_fixed = yaml_.GetDataElement(kCtrNodeStr + "/" + kSysFixedKeyStr);

	u8 aes_key[Crypto::kAes128KeySize];

	// Application Fixed Key
	if (app_fixed != nullptr && !app_fixed->data().empty())
	{
		if (DecodeHexString(app_fixed->data()[0], Crypto::kAes128KeySize, aes_key) != ERR_NOERROR)
		{
			return ERR_DATA_CORRUPT;
		}
		if (AddAesKey(CTR_APP_FIXED_KEY, aes_key, ctr_.fixed_keys))
		{
			return ERR_DATA_ALREADY_EXIST;
		}
	}

	// System Fixed Key
	if (sys_fixed != nullptr && !sys_fixed->data().empty())
	{
		if (DecodeHexString(sys_fixed->data()[0], Crypto::kAes128KeySize, aes_key) != ERR_NOERROR)
		{
			return ERR_DATA_CORRUPT;
		}
		if (AddAesKey(CTR_SYSTEM_FIXED_KEY, aes_key, ctr_.fixed_keys) != ERR_NOERROR)
		{
			return ERR_DATA_ALREADY_EXIST;
		}
	}

	return ERR_NOERROR;
}

int KeyStore::SaveUnfixedKeys()
{
	const YamlElement* ctr_node = yaml_.GetDataElement(kCtrNodeStr);

	if (ctr_node == nullptr)
	{
		return ERR_KSF_ELEMENT_NOT_PRESENT;
	}

	size_t unfixedkey_num = ctr_node->GetChildOccurence(kUnfixedKeyStr);
	for (size_t i = 0; i < unfixedkey_num; i++)
	{
		if (SaveUnfixedKey(ctr_node->GetChild(kUnfixedKeyStr, i)) != ERR_NOERROR)
		{
			return ERR_DATA_ALREADY_EXIST;
		}
	}

	return ERR_NOERROR;
}

int KeyStore::SaveUnfixedKey(const YamlElement* node)
{
	const YamlElement *ksf_key_id, *ksf_key_x;
	u8 key_id, key_x[Crypto::kAes128KeySize];

	if (node == nullptr)
	{
		return ERR_KSF_ELEMENT_NOT_PRESENT;
	}

	ksf_key_id = node->GetChild(kIdStr);
	ksf_key_x = node->GetChild(kAesKeyXStr);

	if (ksf_key_id != nullptr && !ksf_key_id->data().empty())
	{
		key_id = strtol(ksf_key_id->data()[0].c_str(), NULL, 0);
	}
	else
	{
		key_id = 0;
	}

	if (ksf_key_x != nullptr && !ksf_key_x->data().empty())
	{
		DecodeHexString(ksf_key_x->data()[0], Crypto::kAes128KeySize, key_x);
	}
	else
	{
		return ERR_KSF_ELEMENT_NOT_PRESENT;
	}

	return AddAesKey(key_id, key_x, ctr_.unfixed_keys);
}

int KeyStore::AddAesKey(u8 id, const u8* key, std::vector<sAesKey>& key_list)
{
	for (const auto& key : key_list)
	{
		if (key.id == id)
		{
			return ERR_DATA_ALREADY_EXIST;
		}
	}
	sAesKey new_key;

	new_key.id = id;
	memcpy(new_key.key, key, Crypto::kAes128KeySize);

	key_list.push_back(new_key);

	return ERR_NOERROR;
}

int KeyStore::GetAesKey(const std::vector<sAesKey>& key_list, u8 id, u8* key_output)
{
	for (const auto& key : key_list)
	{
		if (key.id == id)
		{
			memcpy(key_output, key.key, Crypto::kAes128KeySize);
			return ERR_NOERROR;
		}
	}
	return ERR_DATA_NOT_EXIST;
}

int KeyStore::AddRsa2048Key(u8 id, const Crypto::sRsa2048Key & key, std::vector<sRsa2048Key>& key_list)
{
	for (const auto& key : key_list)
	{
		if (key.id == id)
		{
			return ERR_DATA_ALREADY_EXIST;
		}
	}
	sRsa2048Key new_key;

	new_key.id = id;
	memcpy(new_key.key.modulus, key.modulus, Crypto::kRsa2048Size);
	memcpy(new_key.key.priv_exponent, key.priv_exponent, Crypto::kRsa2048Size);

	key_list.push_back(new_key);

	return ERR_NOERROR;
}

int KeyStore::GetRsa2048Key(const std::vector<sRsa2048Key>& key_list, u8 id, Crypto::sRsa2048Key& key_output)
{
	for (const auto& key : key_list)
	{
		if (key.id == id)
		{
			memcpy(key_output.modulus, key.key.modulus, Crypto::kRsa2048Size);
			memcpy(key_output.priv_exponent, key.key.priv_exponent, Crypto::kRsa2048Size);
			return ERR_NOERROR;
		}
	}
	return ERR_DATA_NOT_EXIST;
}

int KeyStore::AddRsa4096Key(u8 id, const Crypto::sRsa4096Key & key, std::vector<sRsa4096Key>& key_list)
{
	for (const auto& key : key_list)
	{
		if (key.id == id)
		{
			return ERR_DATA_ALREADY_EXIST;
		}
	}
	sRsa4096Key new_key;

	new_key.id = id;
	memcpy(new_key.key.modulus, key.modulus, Crypto::kRsa4096Size);
	memcpy(new_key.key.priv_exponent, key.priv_exponent, Crypto::kRsa4096Size);

	key_list.push_back(new_key);

	return ERR_NOERROR;
}

int KeyStore::GetRsa4096Key(const std::vector<sRsa4096Key>& key_list, u8 id, Crypto::sRsa4096Key& key_output)
{
	for (const auto& key : key_list)
	{
		if (key.id == id)
		{
			memcpy(key_output.modulus, key.key.modulus, Crypto::kRsa4096Size);
			memcpy(key_output.priv_exponent, key.key.priv_exponent, Crypto::kRsa4096Size);
			return ERR_NOERROR;
		}
	}
	return ERR_DATA_NOT_EXIST;
}

int KeyStore::AddEsCertificate(u8 id, const ESCert& certificate, std::vector<sEsCertificate>& cert_list)
{
	for (size_t i = 0; i < cert_list.size(); i++)
	{
		if (cert_list[i].id == id)
		{
			return ERR_DATA_ALREADY_EXIST;
		}
	}


	cert_list.push_back(sEsCertificate{ id });
	cert_list[cert_list.size() - 1].certificate = certificate;

	return ERR_NOERROR;
}

int KeyStore::GetEsCertificate(const std::vector<sEsCertificate>& cert_list, u8 id, ESCert & cert_output)
{
	for (size_t i = 0; i < cert_list.size(); i++)
	{
		if (cert_list[i].id == id)
		{
			cert_output = cert_list[i].certificate;
			return ERR_NOERROR;
		}
	}
	return ERR_DATA_NOT_EXIST;
}

int KeyStore::DecodeHexString(const std::string& hex_str, size_t len, u8* out)
{
	if (hex_str.size() != len * 2)
	{
		return ERR_DATA_CORRUPT;
	}

	char byte_str[3] = { 0 };

	for (size_t i = 0; i < hex_str.size(); i += 2)
	{
		byte_str[0] = hex_str.c_str()[i];
		byte_str[1] = hex_str.c_str()[i+1];
		out[i/2] = strtol(byte_str, NULL, 16);
	}

	return ERR_NOERROR;
}

void KeyStore::PrintElementLoadFailure(const std::string & element_name, const std::string & failure_reason)
{
	printf("[KEYSTORE ERROR] Failed to load %s, reason: %s\n", element_name.c_str(), failure_reason.c_str());
}

void KeyStore::SetUpYamlLayout(void)
{
	yaml_.AllowDuplicateDataChilds(true);

	yaml_.AddChildToRoot(kEsNodeStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kEsNodeStr, kCommonKeyStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kCommonKeyStr, kIdStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kCommonKeyStr, kAesKeyStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr, kRootKeyStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kRootKeyStr, kModulusStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kRootKeyStr, kPrivateExponentStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr, kCaCertStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr, kCaKeyStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kCaKeyStr, kModulusStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kCaKeyStr, kPrivateExponentStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr, kXsCertStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr, kXsKeyStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kXsKeyStr, kModulusStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kXsKeyStr, kPrivateExponentStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr, kCpCertStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr, kCpKeyStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kCpKeyStr, kModulusStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kEsNodeStr + "/" + kCpKeyStr, kPrivateExponentStr, YamlElement::ELEMENT_SINGLE_KEY);

	yaml_.AddChildToRoot(kCtrNodeStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kCtrNodeStr, kNcsdCfaStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kCtrNodeStr + "/" + kNcsdCfaStr, kModulusStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kCtrNodeStr + "/" + kNcsdCfaStr, kPrivateExponentStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kCtrNodeStr, kAccessDescStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kCtrNodeStr + "/" + kAccessDescStr, kModulusStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kCtrNodeStr + "/" + kAccessDescStr, kPrivateExponentStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kCtrNodeStr, kCrrStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kCtrNodeStr + "/" + kCrrStr, kModulusStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kCtrNodeStr + "/" + kCrrStr, kPrivateExponentStr, YamlElement::ELEMENT_SINGLE_KEY);

	yaml_.AddChildToParent(kCtrNodeStr, kAppFixedKeyStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kCtrNodeStr, kSysFixedKeyStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kCtrNodeStr, kUnfixedKeyStr, YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent(kCtrNodeStr + "/" + kUnfixedKeyStr, kIdStr, YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent(kCtrNodeStr + "/" + kUnfixedKeyStr, kAesKeyXStr, YamlElement::ELEMENT_SINGLE_KEY);
}
