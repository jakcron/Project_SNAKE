#include "UserSettings.h"
#include <keystore/KeyStore.h>
#include <ctr/cia_reader.h>
#include <es/es_version.h>

void nintendoPrintHexArray(const u8* data, size_t size)
{
	for (size_t i = 0; i < size; i++) {
		printf("0x%02x ", data[i]);
	}
}

void nintendoLidFields(const ESTmd& lgy_tmd)
{
	printf("TMD fields:\n");
	printf("  sigType: %x\n", ESCrypto::GetSignatureType(lgy_tmd.GetSerialisedData()));
	printf("  issuer: %s\n", lgy_tmd.GetIssuer().c_str());
	printf("  version: %d\n", lgy_tmd.GetFormatVersion());
	printf("  sysVersion: 0x%llx\n", lgy_tmd.GetSystemVersion());
	printf("  caCrlVersion: %d\n", lgy_tmd.GetCaCrlVersion());
	printf("  signerCrlVersion: %d\n", lgy_tmd.GetSignerCrlVersion());
	printf("  titleType: 0x%08x\n", lgy_tmd.GetTitleType());
	printf("  titleId: 0x%llx\n", lgy_tmd.GetTitleId());
	//printf("   reserved: ");
	//nintendoPrintHexArray(lgy_tmd.GetPlatformReservedData(), lgy_tmd.GetPlatformReservedSize()); printf("\n");
	printf("  groupId: %x%x\n", lgy_tmd.GetCompanyCode().at(0), lgy_tmd.GetCompanyCode().at(1));
	printf("  accessRights: %08x\n", lgy_tmd.GetAccessRights());
	printf("  titleVersion: %d\n", lgy_tmd.GetTitleVersion());
	printf("  numContents: %d\n", lgy_tmd.GetContentNum());
	printf("  bootIndex: %d\n", lgy_tmd.GetBootContentIndex());
	for (size_t i = 0; i < lgy_tmd.GetContentNum(); i++)
	{
		const auto& cnt = lgy_tmd.GetContentList()[i];
		printf("  --cid %d: 0x%08x\n", i, cnt.GetContentId());
		printf("    index %d: %d\n", i, cnt.GetContentIndex());
		printf("    type %d: 0x%x\n", i, cnt.GetFlags());
		printf("    size %d: %d\n", i, cnt.GetSize());
		printf("    hash %d: ", i);
		nintendoPrintHexArray(cnt.GetHash(), Crypto::kSha1HashLen);
		printf("\n");
	}
}

void nintendoLitFields(const ESTicket& lgy_tik)
{
	printf("Ticket fields:\n");
	printf("  sigType: %x\n", ESCrypto::GetSignatureType(lgy_tik.GetSerialisedData()));
	printf("  issuer: %s\n", lgy_tik.GetIssuer().c_str());
	printf("  version: %d\n", lgy_tik.GetFormatVersion());
	printf("  caCrlVersion: %d\n", lgy_tik.GetCaCrlVersion());
	printf("  signerCrlVersion: %d\n", lgy_tik.GetSignerCrlVersion());
	//printf("  serverPubKey: ");
	//nintendoPrintHexArray((const u8*)&lgy_tik.GetServerPublicKey(), Crypto::kEcdsaSize); printf("\n");
	printf("  ticketId: 0x%08x\n", lgy_tik.GetTicketId());
	printf("  deviceId: 0x%08x\n", lgy_tik.GetDeviceId());
	printf("  sysAccessMask: 0x%02x 0x%02x\n", (lgy_tik.GetSystemAccessMask() >> 8 & 0xff), (lgy_tik.GetSystemAccessMask() & 0xff));
	printf("  ticketVersion: %d\n", lgy_tik.GetTitleVersion());
	printf("  accessTitleId: 0x%08x\n", lgy_tik.GetAccessTitleId());
	printf("  accessTitleIdMask: 0x%08x\n", lgy_tik.GetAccessTitleIdMask());
	printf("  licenseType: 0x%x\n", lgy_tik.GetLicenseType());
	printf("  keyId: 0x%x\n", lgy_tik.GetCommonKeyIndex());
	//printf("  reserved: ");
	//nintendoPrintHexArray(lgy_tik.GetReservedData(), lgy_tik.GetReservedDataSize()); printf("\n");
	printf("  audit: 0x%x\n", lgy_tik.GetAudit());
	printf("  titleId: 0x%llx\n", lgy_tik.GetTitleId());
	printf("  cidxList: ");
	for (u16 index : lgy_tik.GetEnabledContentList())
	{
		printf("%d ", index);
	}
	printf("\n");
	printf(" limits: ");
	//for (
	
}

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printf("usage: %s <cia file>\n", argv[0]);
		return 1;
	}


	// keystore
	KeyStore kstr;
	kstr.ParseKeySpecFile("ksf/ctr_devkit.ksf");

	// root key
	Crypto::sRsa4096Key root_key;
	kstr.GetEsRsa4096Key(kstr.ES_IDENT_ROOT, root_key);

	// file reader
	ByteBuffer file;

	// Open CIA
	file.OpenFile(argv[1]);
	CiaReader cia;
	cia.ImportCia(file.data_const());
	
	// Get CommonKey from keyfile
	u8 common_key[Crypto::kAes128KeySize];
	kstr.GetCommonKey(cia.GetCommonKeyIndex(), common_key);
	
	// Get TitleKey using CommonKey
	u8 title_key[Crypto::kAes128KeySize];
	memcpy(title_key, cia.GetTitleKey(common_key), Crypto::kAes128KeySize);

	printf("Chain Of Trust:\n");
	printf(" CERTS: %s\n", cia.ValidateCertificates(root_key) ? "GOOD" : "BAD");
	printf(" TIK:   %s\n", cia.ValidateTicket() ? "GOOD" : "BAD");
	printf(" TMD:   %s\n", cia.ValidateTmd() ? "GOOD" : "BAD");

	CtrProgramId title_id(cia.GetTitleId());
	ESVersion title_ver(cia.GetTitleVersion());

	printf("TitleInfo:\n");
	printf("  ID:   %04x-%04x-%06x-%02x\n", title_id.device_type(), title_id.category(), title_id.unique_id(), title_id.variation());

	// data archive
	if (title_id.IsCategoryBitsSet(CtrProgramId::CATEGORY_FLAG_NOT_EXECUTABLE) && !title_id.IsCategoryBitsSet(CtrProgramId::CATEGORY_FLAG_TWL_TITLE))
	{
		printf("  VER:  %d.%d (v%d)\n", title_ver.data_version(), title_ver.build(), title_ver.version());
	}
	// else executable
	else
	{
		printf("  VER:  %d.%d.%d (v%d)\n", title_ver.major(), title_ver.minor(), title_ver.build(), title_ver.version());
	}
	
	printf("Content:\n");
	for (auto& content: cia.GetContentList())
	{
		if (content.IsFlagSet(content.ES_CONTENT_TYPE_ENCRYPTED))
		{
			content.DecryptContent(title_key);
		}
		printf("  %d:    [id=%08x][flags=%04x][size=0x%llx][enabled=%s][hash=%s]\n", content.GetContentIndex(), content.GetContentId(), content.GetFlags(), content.GetSize(), content.IsContentEnabled()? "YES" : "NO", content.ValidateContentHash()? "GOOD" : "BAD");
		printf(" Writing %04x-%08x.app to file...\n", content.GetContentIndex(), content.GetContentId());
	}

	/*
	EsCertChain certs;
	file.OpenFile("certs.twl");
	certs.DeserialiseCertChain(file.data_const(), file.size());
	for (const auto& cert : certs.GetCertificates())
	{
		printf("CERT:\n");
		printf("  SignType:    %x\n", EsCrypto::GetSignatureType(cert.GetSerialisedData()));
		printf("  Issuer:      %s\n", cert.GetIssuer().c_str());
		printf("  PubKeyType:  %x\n", cert.GetPublicKeyType());
		printf("  Name:        %s\n", cert.GetName().c_str());
		printf("  UniqueId:    %x\n", cert.GetUniqueId());
	}
	for (const auto& cert : cia.GetCertificateChain().GetCertificates())
	{
		printf("CERT:\n");
		printf("  SignType:    %x\n", EsCrypto::GetSignatureType(cert.GetSerialisedData()));
		printf("  Issuer:      %s\n", cert.GetIssuer().c_str());
		printf("  PubKeyType:  %x\n", cert.GetPublicKeyType());
		printf("  Name:        %s\n", cert.GetName().c_str());
		printf("  UniqueId:    %x\n", cert.GetUniqueId());
	}
	*/

	/*
	KeyStore twl_kstore;
	twl_kstore.ParseKeySpecFile("ksf/twl_devkit.ksf");
	EsCert xsCert;
	Crypto::sRsa2048Key xsKey;
	twl_kstore.GetEsCert(KeyStore::ES_IDENT_XS, xsCert);
	twl_kstore.GetEsRsa2048Key(KeyStore::ES_IDENT_XS, xsKey);


	
	file.OpenFile("lgy.tik");
	EsTicket lgy_tik;
	lgy_tik.DeserialiseTicket(file.data_const());
	nintendoLitFields(lgy_tik);
	//twl_kstore.GetCommonKey(0, common_key);
	//nintendoPrintHexArray(lgy_tik.GetTitleKey(common_key), 16);
	*/

	/*
	KeyStore twl_kstore;
	twl_kstore.ParseKeySpecFile("ksf/twl_devkit.ksf");
	EsCert cpCert;
	Crypto::sRsa2048Key cpKey;
	twl_kstore.GetEsCert(KeyStore::ES_IDENT_CP, cpCert);
	twl_kstore.GetEsRsa2048Key(KeyStore::ES_IDENT_CP, cpKey);

	//certs.AddCertificate(cpCert);
	//certs.SerialiseCertChain();

	file.OpenFile("lgy.tmd");
	EsTmd lgy_tmd;
	lgy_tmd.DeserialiseTmd(file.data_const());
	nintendoLidFields(lgy_tmd);


	lgy_tmd.SetTitleVersion(1337);
	lgy_tmd.SerialiseTmd(cpKey, EsTmd::ES_TMD_VER_1);

	nintendoLidFields(lgy_tmd);
	*/

	return 0;

	UserSettings userset;

	return userset.ParseUserArgs(argc, argv);
}