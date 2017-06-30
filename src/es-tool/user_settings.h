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

	UserSettings();
	UserSettings(int argc, char** argv);
	~UserSettings();


	void parseCliArgs(int argc, char** argv);
	
	
	const std::string& getInFilePath() const;
	const std::string& getOutFilePath() const;
	FileType getFileType() const;

	bool doPrintData() const;
	bool doShowSignatures() const;
	bool doShowFullPublicKeys() const;
	bool doShowCdnCerts() const;
	bool doUseCdnCertToVerify() const;
	bool doUseExternalCertToVerify() const;
	const std::string& getExternalCertPath() const;

	// general data fields
	void setFormatVersion(u8 version);
	u8 getFormatVersion() const;
	void setTitleId(u64 title_id);
	u64 getTitleId() const;
	void setVersion(u16 version);
	u16 getVersion() const;
	void setCaCrlVersion(u8 crl_version);
	u8 getCaCrlVersion() const;
	void setSignerCrlVersion(u8 crl_version);
	u8 getSignerCrlVersion() const;

	// ticket data fields
	void setTicketId(u64 ticket_id);
	u64 getTicketId() const;
	void setTitleKey(const u8* title_key);
	const u8* getTitleKey() const;
	void setEscrowKey(const u8* escrow_key);
	const u8* getEscrowKey() const;
	void setEscrowKeyId(u8 key_id);
	void setEscrowedTitleKey(const u8* escrowed_key);
	const u8* getEscrowedTitleKey() const;
	u8 getEscrowKeyId() const;
	void setDeviceId(u32 device_id);
	u32 getDeviceId() const;
	void setSystemAccessibleContent(const std::vector<u16>& content_index);
	const std::vector<u16>& getSystemAccessibleContent() const;
	void setAccessTitleId(u32 id);
	u32 getAccessTitleId() const;
	void setAccessTitleIdMask(u32 id_mask);
	u32 getAccessTitleIdMask() const;
	void setLicenseType(ESTicket::ESLicenseType type);
	ESTicket::ESLicenseType getLicenseType() const;
	void setEShopAccountId(u32 id);
	u32 getEShopAccountId() const;
	void setAudit(u8 audit);
	u8 getAudit() const;
	void setLimits(std::vector<sESLimit>& limits);
	const std::vector<sESLimit>& getLimits() const;



private:	
	const std::string kModuleName = "USER_SETTINGS";
	static const int kVersionMajor = 0;
	static const int kVersionMinor = 1;

	// user settings
	
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
			if (!is_set)
				throw ProjectSnakeException(kModuleName, name_ + " not set");
			return data_;
		}
	private:
		std::string name_;
		bool is_set_;
		T data_;
	};

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
		bool show_cdn_certs_;
		bool use_cdn_certs_;
		std::string certs_path_;
	} cli_output_;

	struct sSharedOptions
	{
		sSharedOptions() :
			format_version_("Format Version"),
			title_id_("Title ID"),
			version_("Title Version"),
			ca_crl_version_("CA CRL Version"),
			signer_crl_version_("Signer CRL Version")
		{
		}

		SettableObject<u8> format_version_;
		SettableObject<u64> title_id_;
		SettableObject<u16> version_;
		SettableObject<u8> ca_crl_version_;
		SettableObject<u8> signer_crl_version_;
	} shared_;

	struct sTicketOptions
	{
		sTicketOptions() :
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
		SettableObject<u32[ESTicket::ESLimitCode::ES_MAX_LIMIT_TYPE]> limits_;
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

	void showCliHelp(const std::string& name);
	void clearSettings();
};