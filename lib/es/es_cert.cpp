#include "es_cert.h"

EsCert::EsCert()
{
	Clear();
}

EsCert::~EsCert()
{
	Clear();
}

void EsCert::Clear()
{
	memset(child_issuer_, 0, kStringMax);
}

int EsCert::ImportCert(const void * cert)
{
	// check if the signature header is valid by attempting to get a pointer the the body
	if (EsCrypto::GetSignedBinaryBody(cert) == nullptr) 
	{
		return ERR_INVALID_SIGNATURE_HEADER;
	}

	// get temporary pointer to body_
	//sCertificateBody body;
	//memcpy(&body, EsCrypto::GetSignedBinaryBody(cert), sizeof(sCertificateBody));
	body_ = (sCertificateBody*)EsCrypto::GetSignedBinaryBody(cert);


	// check that the public key type is valid
	if (GetPublicKeySize(public_key_type()) == 0) 
	{
		return ERR_INVALID_PUBLIC_KEY_TYPE;
	}

	// determine certificate size
	cert_size_ = EsCrypto::GetSignatureSize(cert) + sizeof(sCertificateBody) + GetPublicKeySize(public_key_type());
	if (cert_size_ > kBufferLen)
	{
		return ERR_CERTIFICATE_TOO_LARGE;
	}

	// save copy of certificate
	memcpy(cert_, cert, cert_size_);


	// save pointers for body and public key location
	body_ = (sCertificateBody*)(cert_ + EsCrypto::GetSignatureSize(cert));
	public_key_ = cert_ + (EsCrypto::GetSignatureSize(cert) + sizeof(sCertificateBody));

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
