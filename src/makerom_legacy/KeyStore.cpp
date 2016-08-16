#include "YamlFile.h"

KeyStore::KeyStore()
{
	SetUpYamlLayout();
}

KeyStore::~KeyStore()
{
}

int KeyStore::ParseKeySpecFile(const char * path)
{
	if (yaml_.ParseFile(path) != 0) 
	{
		return 1;
	}

	// process common keys
	// process es certs and keys

	// process ctr rsa keys
	// process ctr aes keys

	return 0;
}

void KeyStore::SetUpYamlLayout(void)
{
	yaml_.AllowDuplicateDataChilds(true);

	yaml_.AddChildToRoot("EsPki", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("EsPki", "CommonKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("EsPki/CommonKey", "Index", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki/CommonKey", "AesKey", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki", "RootKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("EsPki/RootKey", "N", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki/RootKey", "D", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki", "CaCert", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki", "CaKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("EsPki/CaKey", "N", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki/CaKey", "D", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki", "TikCert", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki", "TikKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("EsPki/TikKey", "N", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki/TikKey", "D", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki", "TmdCert", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki", "TmdKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("EsPki/TmdKey", "N", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("EsPki/TmdKey", "D", YamlElement::ELEMENT_SINGLE_KEY);

	yaml_.AddChildToRoot("CtrRsa", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("CtrRsa", "NcsdCfaKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("CtrRsa/NcsdCfaKey", "N", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CtrRsa/NcsdCfaKey", "D", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CtrRsa", "AccessDescriptorKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("CtrRsa/AccessDescriptorKey", "N", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CtrRsa/AccessDescriptorKey", "D", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CtrRsa", "CrrKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("CtrRsa/CrrKey", "N", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CtrRsa/CrrKey", "D", YamlElement::ELEMENT_SINGLE_KEY);

	yaml_.AddChildToRoot("CtrAes", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("CtrAes", "AppFixedKey", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CtrAes", "SystemFixedKey", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CtrAes", "UnfixedKey", YamlElement::ELEMENT_NODE);
	yaml_.AddChildToParent("CtrAes/UnfixedKey", "Index", YamlElement::ELEMENT_SINGLE_KEY);
	yaml_.AddChildToParent("CtrAes/UnfixedKey", "AesKeyX", YamlElement::ELEMENT_SINGLE_KEY);
}
