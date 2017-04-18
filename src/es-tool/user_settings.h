#pragma once
#include <fnd/types.h>
#include <crypto/crypto.h>
#include <es/es_ticket.h>
#include <vector>

class UserSettings
{
public:
	template <class T>
	struct sSettableValue
	{
		T data_;
		bool is_set_;
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


	void ParseCliArgs(int argc, char** argv);
	
	
	const std::string& GetInFilePath() const;
	const std::string& GetOutFilePath() const;
	FileType GetFileType() const;

	bool DoPrintData() const;
	bool DoShowSignatures() const;
	bool DoShowFullPublicKeys() const;
	bool DoShowCdnCerts() const;
	bool DoUseCdnCertToVerify() const;
	bool DoUseExternalCertToVerify() const;
	const std::string& GetExternalCertPath() const;

	// general data fields
	bool IsFormatVersionSet() const;
	u8 GetFormatVersion() const;
	bool IsTitleIdSet() const;
	u64 GetTitleId() const;
	bool IsVersionSet() const;
	u16 GetVersion() const;

	// ticket data fields
	bool IsTicketIdSet() const;


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
		bool show_cdn_certs_;
		bool use_cdn_certs_;
		std::string certs_path_;
	} cli_output_;

	struct sSharedOptions
	{
		sSettableValue<u8> format_version_;
		sSettableValue<u64> title_id_;
		sSettableValue<u16> version_;
		sSettableValue<u8> ca_crl_version_;
		sSettableValue<u8> signer_crl_version_;
	} shared_;

	struct sTicketOptions
	{
		sSettableValue<u64> ticket_id_;
		sSettableValue<u8[Crypto::kAes128KeySize]> title_key_;
		sSettableValue<u8[Crypto::kAes128KeySize]> escrow_key_;
		sSettableValue<u8> escrow_key_id_;
		sSettableValue<u32> device_id_;
		sSettableValue<std::vector<u16>> system_accessible_content_;
		sSettableValue<u32> access_title_id_;
		sSettableValue<u32> access_title_id_mask_;
		sSettableValue<ESTicket::ESLicenseType> license_type_;
		sSettableValue<u32> eshop_act_id_;
		sSettableValue<u8> audit_;
		sSettableValue<u32[ESTicket::ESLimitCode::ES_MAX_LIMIT_TYPE]> limits_;
		sSettableValue<std::vector<u16>> enabled_content_;

	} ticket_;

	void ShowCliHelp(const std::string& name);
	void ClearSettings();
};