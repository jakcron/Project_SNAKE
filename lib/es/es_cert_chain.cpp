#include "es_cert_chain.h"



EsCertChain::EsCertChain()
{
}


EsCertChain::~EsCertChain()
{
}

const EsCert & EsCertChain::operator[](size_t index) const
{
	if (index >= certs_.size())
	{
		throw ProjectSnakeException(kModuleName, "Illegal array index");
	}
	
	return certs_[index];
}

const EsCert & EsCertChain::operator[](const std::string & signer) const
{
	for (const auto& cert : certs_)
	{
		if (cert.GetChildIssuer() == signer)
		{
			return cert;
		}
	}

	throw ProjectSnakeException(kModuleName, "Certificate (" + signer + ") does not exist");
}

const u8* EsCertChain::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t EsCertChain::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void EsCertChain::SerialiseCertChain()
{
	size_t total_size = 0;
	for (const auto& cert : certs_)
	{
		total_size += cert.GetSerialisedDataSize();
	}

	// allocate memory for serialised data
	if (serialised_data_.alloc(total_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for certificate chain");
	}

	size_t write_pos = 0;
	for (const auto& cert : certs_)
	{
		memcpy(serialised_data_.data() + write_pos, cert.GetSerialisedData(), cert.GetSerialisedDataSize());
		write_pos += cert.GetSerialisedDataSize();
	}
}

void EsCertChain::AddCertificate(const u8* cert_data)
{
	EsCert cert;
	cert.DeserialiseCert(cert_data);
	certs_.push_back(cert);
}

void EsCertChain::AddCertificate(const EsCert & cert)
{
	AddCertificate(cert.GetSerialisedData());
}

void EsCertChain::DeserialiseCertChain(const u8* data, size_t size)
{
	size_t read_size = 0;
	while ((size - read_size) > 0x40)
	{
		AddCertificate(data + read_size);
		read_size += certs_[certs_.size()-1].GetSerialisedDataSize();
	}

	if (serialised_data_.alloc(read_size) != serialised_data_.ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for certificate chain");
	}

	memcpy(serialised_data_.data(), data, read_size);
}

bool EsCertChain::ValidateChain(const Crypto::sRsa4096Key& root_key) const
{
	int fail_count = 0;
	for (size_t i = 0; i < certs_.size(); i++)
	{
		if (certs_[i].GetIssuer() == kCaCertIssuer)
		{
			if (!certs_[i].ValidateSignature(root_key))
			{
				fail_count++;
			}
		}
		else
		{
			if (!certs_[i].ValidateSignature((*this)[certs_[i].GetIssuer()]))
			{
				fail_count++;
			}
		}
	}
	return fail_count == 0;
}

bool EsCertChain::ValidateChainExceptCa() const
{
	int fail_count = 0;
	for (size_t i = 0; i < certs_.size(); i++)
	{
		if (certs_[i].GetIssuer() == kCaCertIssuer)
		{
			continue;
		}
		else
		{
			if (!certs_[i].ValidateSignature((*this)[certs_[i].GetIssuer()]))
			{
				fail_count++;
			}
		}
	}
	return fail_count == 0;
}

const std::vector<EsCert>& EsCertChain::GetCertificates() const
{
	return certs_;
}

size_t EsCertChain::GetCertificateNum() const
{
	return certs_.size();
}
