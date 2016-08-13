#pragma once
#include <string>
#include <vector>
#include "types.h"

#include "ByteBuffer.h"
#include "RsfSettings.h"
#include "KeyStore.h"

class UserSettings
{
public:
	enum ErrorCode
	{
		ERR_NOERROR,
		ERR_ARGV_NULLPTR,
		ERR_MALLOC_FAIL,
		ERR_USR_HELP,
		ERR_INVALID_ARG,
	};

	UserSettings();
	~UserSettings();

	int ParseUserArgs(int argc, char** argv);
	void DisplayHelp(const char* bin_path, bool extended_help);

private:
	enum FileType
	{
		FILE_UNDEFINED,
		FILE_NCCH_GENERIC,
		FILE_CXI,
		FILE_CFA,
		FILE_CCI,
		FILE_CIA,
		FILE_TMD,
		FILE_TIK,
		FILE_SRL,
		FILE_TAD,
	};

	struct sInputContentInfo
	{
		std::string path;
		u32 id;
		u16 index;
		u64 size;
	};

	struct sRsfStringSubstitute
	{
		std::string name;
		std::string value;
	};

	struct sCommonSettings 
	{
		bool verbose;

		std::string rsf_path;
		std::string ksf_path;
		std::string output_path;
		FileType output_type;

		KeyStore keystore;

		RsfSettings rsf_settings;
		std::vector<sRsfStringSubstitute> rsf_substitutes;

		std::vector<sInputContentInfo> contents;

		std::string input_path;
		FileType input_type;
		ByteBuffer input_file;
	} common_;

	struct sNcchSettings
	{
		bool build_ncch;
		FileType ncch_type;
		std::string elf_path;
		std::string icon_path;
		std::string banner_path;
		std::string desc_path;

		bool include_exefs_logo; // for <5.x compatibility

		// ncch rebuild settings
		std::string code_path;
		std::string exheader_path;
		std::string plain_region_path;
		std::string romfs_path;
	} ncch_;

	struct sCciSettings
	{
		bool use_sdk_stock_data;
		bool no_modify_ncch_title_id;
		bool close_align_writeable_region;
	} cci_;

	struct sCiaSettings
	{
		bool random_title_key;
		bool encrypt_content;
		bool dlc_title;
		u8 commonkey_index;
		
		u16 title_version;

		u32 device_id;
	} cia_;

	int ProcessArgument(int argc, int argp, char** argv);
	int PostProcessArguments();

	const char* GetFileTypeExtention(FileType file_type);

	void ErrorInvalidParamNum(const char* arg, int valid_param_num);
};