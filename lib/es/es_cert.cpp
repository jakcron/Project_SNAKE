#include "es_cert.h"

EsCert::EsCert()
{
}

EsCert::~EsCert()
{
}

int EsCert::ImportCert(const void * cert)
{
	if (EsCrypto::GetSignedBinaryBody(cert) == nullptr) {
		return 1;
	}

	// copy certificate body into internal member 
	memcpy(&body_, EsCrypto::GetSignedBinaryBody(cert), sizeof(sCertificateBody));


	// check that the public key type is valid
	if (GetPublicKeySize(public_key_type()) == 0) {
		return 1;
	}

	// allocate memory for and save public key
	public_key_.alloc(GetPublicKeySize(public_key_type()));
	memcpy(public_key_.data(), ((const u8*)EsCrypto::GetSignedBinaryBody(cert)) + sizeof(sCertificateBody), public_key_.size());

	// allocate memory for and save complete certificate blob
	blob_.alloc(EsCrypto::GetSignatureSize(cert) + sizeof(sCertificateBody) + public_key_.size());
	memcpy(blob_.data(), cert, blob_.size());

	// generate issuer to be used by child signed binaries
	snprintf(child_issuer_, kStringMax, "%s-%s", issuer(), name());

	return 0;
}

u32 EsCert::GetPublicKeySize(PublicKeyType type)
{
	switch (type)
	{
	case (RSA_4096):
		return sizeof(sRsa2048PublicKeyBody);
	case (RSA_2048):
		return sizeof(sRsa2048PublicKeyBody);
	case (ECDSA):
		return sizeof(sEcdsaPublicKeyBody);
	default:
		return 0;
	}

	return 0;
}
