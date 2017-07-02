#pragma once
#include <fnd/types.h>
#include <fnd/memory_blob.h>
#include <crypto/crypto.h>
#include <es/es_ticket.h>
#include <es/es_tmd.h>
#include <vector>

class UserSettings
{
public:
	// TODO: Move enum to crypto.h
	enum SignType
	{
		SIGN_RSA_1024,
		SIGN_RSA_2048,
		SIGN_RSA_4096,
		SIGN_ECDSA_240
	};

	// TODO: make ESTicket::sLimit variant public, and use instead
	struct sESLimit
	{
		ESTicket::ESLimitCode key;
		u32 value;
	};

	enum FileType
	{
		FILE_INVALID,
		FILE_CERTS,
		FILE_TIK,
		FILE_TMD
	};

	// SettableValue only primative or classes, no literal arrays.
	template <class T>
	class SettableObject
	{
	public:
		SettableObject(const std::string& name) :
			name_(name),
			is_set_(false)
		{
		}

		void operator=(const T& data)
		{
			set(data);
		}

		inline bool is_set() const 
		{
			return is_set_;
		}

		inline void set(const T& data)
		{
			data_ = data;
			is_set_ = true;
		}

		inline T& get_unsafe()
		{
			return data_;
		}

		inline const T& get() const
		{ 
			if (!is_set_)
				throw ProjectSnakeException("USER_SETTINGS", name_ + " not set");
			return data_;
		}
	private:
		std::string name_;
		bool is_set_;
		T data_;
	};

	UserSettings();
	UserSettings(int argc, char** argv);
	~UserSettings();

	/// Parse CLI arguments
	void parseCliArgs(int argc, char** argv);
	
	/// input/output and file type
	const std::string& getInFilePath() const;
	const std::string& getOutFilePath() const;
	FileType getFileType() const;

	/// output settings
	bool doPrintData() const;
	bool doShowSignatures() const;
	bool doShowFullPublicKeys() const;
	bool doShowCerts() const;
	bool doUseCdnCertToVerify() const;
	bool doUseExternalCertToVerify() const;
	const std::string& getExternalCertPath() const;

	// general data fields
	const SettableObject<SignType>& getSignType() const;
	void setSigningKey(const Crypto::sRsa4096Key& key);
	const SettableObject<Crypto::sRsa4096Key>& getSigningKeyRsa4096() const;
	void setSigningKey(const Crypto::sRsa2048Key& key);
	const SettableObject<Crypto::sRsa2048Key>& getSigningKeyRsa2048() const;
	void setSigningKey(const Crypto::sEccPrivateKey& key);
	const SettableObject<Crypto::sEccPrivateKey>& getSigningKeyEcdsa() const;
	void setIssuer(const std::string& issuer);
	const SettableObject<std::string>& getIssuer() const;
	void setFormatVersion(u8 version);
	const SettableObject<u8>& getFormatVersion() const;
	void setTitleId(u64 title_id);
	const SettableObject<u64>& getTitleId() const;
	void setTitleVersion(u16 version);
	const SettableObject<u16>& getTitleVersion() const;
	void setCaCrlVersion(u8 crl_version);
	const SettableObject<u8>& getCaCrlVersion() const;
	void setSignerCrlVersion(u8 crl_version);
	const SettableObject<u8>& getSignerCrlVersion() const;

	// ticket data fields
	void setServerPublicKey(const Crypto::sEccPoint& public_key);
	const SettableObject<Crypto::sEccPoint>& getServerPublicKey() const;
	void setTicketId(u64 ticket_id);
	const SettableObject<u64>& getTicketId() const;
	void setTitleKey(const u8* title_key);
	const SettableObject<MemoryBlob>& getTitleKey() const;
	void setEscrowKey(const u8* escrow_key);
	const SettableObject<MemoryBlob>& getEscrowKey() const;
	void setEscrowKeyId(u8 key_id);
	const SettableObject<u8>& getEscrowKeyId() const;
	void setEscrowedTitleKey(const u8* escrowed_key);
	const SettableObject<MemoryBlob>& getEscrowedTitleKey() const;
	void setDeviceId(u32 device_id);
	const SettableObject<u32>& getDeviceId() const;
	void setSystemAccessibleContentList(const std::vector<u16>& content_index);
	const SettableObject<std::vector<u16>>& getSystemAccessibleContentList() const;
	void setAccessTitleId(u32 id);
	const SettableObject<u32>& getAccessTitleId() const;
	void setAccessTitleIdMask(u32 id_mask);
	const SettableObject<u32>& getAccessTitleIdMask() const;
	void setLicenseType(ESTicket::ESLicenseType type);
	const SettableObject<ESTicket::ESLicenseType>& getLicenseType() const;
	void setEShopAccountId(u32 id);
	const SettableObject<u32>& getEShopAccountId() const;
	void setAudit(u8 audit);
	const SettableObject<u8>& getAudit() const;
	void setLimits(const std::vector<sESLimit>& limits);
	const SettableObject<std::vector<sESLimit>>& getLimits() const;
	void setAccessibleContentList(const std::vector<u16>& content_index);
	const SettableObject<std::vector<u16>>& getAccessibleContentList() const;

private:	
	const std::string kModuleName = "USER_SETTINGS";
	static const int kVersionMajor = 0;
	static const int kVersionMinor = 1;

	// user settings
	struct sGeneralSettings
	{
		FileType file_type_;
		std::string infile_path_;
		std::string outfile_path_;
	} general_;

	struct sCliOutputSettings
	{
		bool print_fields_;
		bool verbose_;
		bool show_signatures_;
		bool full_public_keys_;
		bool show_certs_;
		bool use_cdn_certs_;
		std::string certs_path_;
	} cli_output_;

	struct sSharedOptions
	{
		sSharedOptions() :
			issuer_("Issuer"),
			sign_type_("Signature Type"),
			rsa4096_key_("RSA-4096 Signer Key"),
			rsa2048_key_("RSA-2048 Signer Key"),
			ecdsa240_key_("ECDSA-240 Signer Key"),
			format_version_("Format Version"),
			title_id_("Title ID"),
			version_("Title Version"),
			ca_crl_version_("CA CRL Version"),
			signer_crl_version_("Signer CRL Version")
		{
		}

		SettableObject<std::string> issuer_;
		SettableObject<SignType> sign_type_;
		SettableObject<Crypto::sRsa4096Key> rsa4096_key_;
		SettableObject<Crypto::sRsa2048Key> rsa2048_key_;
		SettableObject<Crypto::sEccPrivateKey> ecdsa240_key_;
		SettableObject<u8> format_version_;
		SettableObject<u64> title_id_;
		SettableObject<u16> version_;
		SettableObject<u8> ca_crl_version_;
		SettableObject<u8> signer_crl_version_;
	} shared_;

	struct sTicketOptions
	{
		sTicketOptions() :
			server_public_key_("Server Public Key"),
			ticket_id_("Ticket ID"),
			title_key_("Title Key"),
			escrow_key_("Escrow Key"),
			escrow_key_id_("Escrow Key ID"),
			escrowed_title_key_("Escrowed Title Key"),
			device_id_("Device ID"),
			system_accessible_content_("System Accessible Content"),
			access_title_id_("Access Title ID"),
			access_title_id_mask_("Access Title ID Mask"),
			license_type_("Type"),
			eshop_act_id_("eShop Account ID"),
			audit_("Audit"),
			limits_("Limits"),
			enabled_content_("Accessible Content")
		{
		}

		SettableObject<Crypto::sEccPoint> server_public_key_;
		SettableObject<u64> ticket_id_;
		SettableObject<MemoryBlob> title_key_;
		SettableObject<MemoryBlob> escrow_key_;
		SettableObject<u8> escrow_key_id_;
		SettableObject<MemoryBlob> escrowed_title_key_;
		SettableObject<u32> device_id_;
		SettableObject<std::vector<u16>> system_accessible_content_;
		SettableObject<u32> access_title_id_;
		SettableObject<u32> access_title_id_mask_;
		SettableObject<ESTicket::ESLicenseType> license_type_;
		SettableObject<u32> eshop_act_id_;
		SettableObject<u8> audit_;
		SettableObject<std::vector<sESLimit>> limits_;
		SettableObject<std::vector<u16>> enabled_content_;

	} ticket_;

	struct sTmdOptions
	{
		sTmdOptions() :
			system_version_("System Version"),
			title_type_("Title Type"),
			company_code_("Company Code"),
			ctr_save_size_("CTR Save Size"),
			twl_public_save_size_("TWL Public Save Size"),
			twl_private_save_size_("TWL Private Save Size"),
			access_rights_("Access Rights")
		{
		}

		SettableObject<u64> system_version_;
		SettableObject<ESTmd::ESTitleType> title_type_;
		SettableObject<std::string> company_code_;
		SettableObject<u32> ctr_save_size_;
		SettableObject<u32> twl_public_save_size_;
		SettableObject<u32> twl_private_save_size_;
		SettableObject<u32> access_rights_;
	} tmd_;

	void setSignType(SignType type);

	void showCliHelp(const std::string& name);
	void clearSettings();
};