#include "UserSettings.h"
#include "es_version.h"

UserSettings::UserSettings()
{
	common_.verbose = false;
	common_.output_type = FILE_NCCH_GENERIC;
	common_.input_type = FILE_UNDEFINED;

	ncch_.build_ncch = false;
	ncch_.ncch_type = FILE_NCCH_GENERIC;


	cia_.commonkey_index = 0;
	cia_.random_title_key = false;
	cia_.encrypt_content = false;

	cia_.device_id = 0;
	cia_.title_version = EsVersion::make_version(0,0,0);
}

UserSettings::~UserSettings()
{
}

int UserSettings::ParseUserArgs(int argc, char** argv)
{
	if (argv == NULL)
		return ERR_ARGV_NULLPTR;

	if (argc < 2) {
		DisplayHelp(argv[0], false);
		return ERR_USR_HELP;
	}

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-help") == 0) {
			DisplayHelp(argv[0], false);
			return ERR_USR_HELP;
		}
		else if (strcmp(argv[i], "-exthelp") == 0) {
			DisplayHelp(argv[0], true);
			return ERR_USR_HELP;
		}
	}

	for (int argp = 1, argp_incr; argp < argc; argp += argp_incr) {
		argp_incr = ProcessArgument(argc, argp, argv);
		if (argp_incr < 1) {
			return ERR_INVALID_ARG;
		}
	}

	PostProcessArguments();

	return ERR_NOERROR;
}

void UserSettings::DisplayHelp(const char * bin_path, bool extended_help)
{
	printf("CTR MAKEROM v0.16 (C) jakcron 2016\n");
	printf("Built: %s %s\n\n", __TIME__, __DATE__);

	printf("Usage: %s [options... ]\n", bin_path);
	printf("Option          Parameter           Explanation\n");
	printf("GLOBAL OPTIONS:\n");
	printf(" -help                              Display simple usage help\n");
	printf(" -exthelp                           Display this text\n");
	printf(" -rsf           <file>              ROM Spec File (*.rsf)\n");
	printf(" -ksf           <file>              Key Spec File (*.ksf)\n");
	printf(" -f             <ncch|cci|cia>      Output format, defaults to 'ncch'\n");
	printf(" -o             <file>              Output file\n");
	printf(" -v                                 Verbose output\n");
	printf(" -DNAME=VALUE                       Substitute values in RSF file\n");
	
	printf("NCCH OPTIONS:\n");
	printf(" -elf           <file>              ELF file\n");
	printf(" -icon          <file>              Icon file\n");
	printf(" -banner        <file>              Banner file\n");
	printf(" -desc          <file>              Specify template spec file (*.desc)\n");
	if (extended_help) {
		printf(" -exefslogo                         Include Logo in ExeFS (Required for usage on <5.0 systems)\n");
	}
	printf("NCCH REBUILD OPTIONS:\n");
	printf(" -code          <file>              Decompressed ExeFS \".code\"\n");
	printf(" -exheader      <file>              Exheader template\n");
	if (extended_help) {
		printf(" -plainrgn      <file>              Plain Region binary\n");
	}
	printf(" -romfs         <file>              RomFS binary\n");
	if (extended_help) {
		printf("CCI OPTIONS:\n");
		printf(" -content       <file>:<index>      Specify content files\n");
		printf(" -devcci                            Use static CTR-SDK cart data\n");
		printf(" -nomodtid                          Don't Modify Content TitleIDs\n");
		printf(" -alignwr                           Align writeable region to the end of last NCCH\n");
		printf("CIA OPTIONS:\n");
		printf(" -content       <file>:<index>:<id> Specify content files\n");
		printf(" -ver           <version>           Title Version\n");
		printf(" -major         <version>           Major version\n");
		printf(" -minor         <version>           Minor version\n");
		printf(" -micro         <version>           Micro version\n");
		printf(" -dver          <version>           Data-title version\n");
		printf(" -deviceid      <hex id>            Lock content to specific device\n");
		printf(" -dlc                               Create DLC CIA\n");
		//printf(" -srl           <srl file>          Package a TWL SRL in a CIA\n");
		//printf(" -tad           <tad file>          Repackage a TWL TAD as a CIA\n");
		printf("NCCH CONTAINER CONVERSION:\n");
		//printf(" -ccitocia      <cci file>          Convert CCI to CIA\n");
		//printf(" -ciatocci      <cia file>          Convert CIA to CCI\n");
	} 
	else {
		printf("CIA/CCI OPTIONS:\n");
		printf(" -content       <file>:<index>      Specify content files\n");
		printf(" -ver           <version>           Title Version\n");
	}
	
}

int UserSettings::ProcessArgument(int argc, int argp, char ** argv)
{
	int arg_param_num = 0;
	for (int i = argp + 1; i < argc && argv[i][0] != '-'; i++)
		arg_param_num++;

#define SUCCESS_RET (arg_param_num+1)
#define FAIL_RET (0)
#define GET_ARG (argv[argp])
#define MATCH_ARG(arg) (strcmp(argv[argp], (arg)) == 0)
#define PARAM_CHECK(valid_num) if (arg_param_num != (valid_num)) { ErrorInvalidParamNum(argv[argp], (valid_num)); return FAIL_RET;}
#define GET_PARAM(index) (argv[argp + (index) + 1])
#define MATCH_PARAM(param, index) (strcmp(GET_PARAM((index)), (param)) == 0)


	// common options
	if (MATCH_ARG("-rsf")) {
		PARAM_CHECK(1);
		common_.rsf_path = GET_PARAM(0);

		return 2;
	}
	else if (MATCH_ARG("-ksf")) {
		PARAM_CHECK(1);
		common_.ksf_path = GET_PARAM(0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-f")) {
		PARAM_CHECK(1);

		if (MATCH_PARAM("ncch", 0) || MATCH_PARAM("cxi", 0) || MATCH_PARAM("cfa", 0) || MATCH_PARAM("exec", 0) || MATCH_PARAM("data", 0)) {
			common_.output_type = FILE_NCCH_GENERIC;
		}
		else if (MATCH_PARAM("cci", 0)) {
			common_.output_type = FILE_CCI;
		}
		else if (MATCH_PARAM("cia", 0)) {
			common_.output_type = FILE_CIA;
		}

		else {
			fprintf(stderr, "[MAKEROM ERROR] Invalid output format \"%s\"\n", GET_PARAM(0));
			return FAIL_RET;
		}

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-o")) {
		PARAM_CHECK(1);
		common_.output_path = GET_PARAM(0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-v")) {
		PARAM_CHECK(0);
		common_.verbose = true;

		return SUCCESS_RET;
	}

	// ncch options
	else if (MATCH_ARG("-elf")) {
		PARAM_CHECK(1);
		ncch_.elf_path = GET_PARAM(0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-icon")) {
		PARAM_CHECK(1);
		ncch_.icon_path = GET_PARAM(0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-banner")) {
		PARAM_CHECK(1);
		ncch_.banner_path = GET_PARAM(0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-desc")) {
		PARAM_CHECK(1);
		ncch_.desc_path = GET_PARAM(0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-exefslogo")) {
		PARAM_CHECK(0);
		ncch_.include_exefs_logo = true;

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-code")) {
		PARAM_CHECK(1);
		ncch_.code_path = GET_PARAM(0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-exheader")) {
		PARAM_CHECK(1);
		ncch_.exheader_path = GET_PARAM(0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-plainrgn")) {
		PARAM_CHECK(1);
		ncch_.plain_region_path = GET_PARAM(0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-romfs")) {
		PARAM_CHECK(1);
		ncch_.romfs_path = GET_PARAM(0);

		return SUCCESS_RET;
	}

	// cci options
	else if (MATCH_ARG("-devcci")) {
		PARAM_CHECK(0);
		cci_.use_sdk_stock_data = true;

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-nomodtid")) {
		PARAM_CHECK(0);
		cci_.no_modify_ncch_title_id = true;

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-alignwr")) {
		PARAM_CHECK(0);
		cci_.close_align_writeable_region = true;

		return SUCCESS_RET;
	}

	// cia options
	else if (MATCH_ARG("-ver")) {
		PARAM_CHECK(1);
		cia_.title_version = strtol(GET_PARAM(0), NULL, 0);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-major")) {
		PARAM_CHECK(1);
		cia_.title_version = EsVersion::make_version(strtol(GET_PARAM(0), NULL, 0), EsVersion::get_minor(cia_.title_version), EsVersion::get_build(cia_.title_version));

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-minor")) {
		PARAM_CHECK(1);
		cia_.title_version = EsVersion::make_version(EsVersion::get_major(cia_.title_version), strtol(GET_PARAM(0), NULL, 0), EsVersion::get_build(cia_.title_version));

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-build")) {
		PARAM_CHECK(1);
		cia_.title_version = EsVersion::make_version(EsVersion::get_major(cia_.title_version), EsVersion::get_minor(cia_.title_version), strtol(GET_PARAM(0), NULL, 0));

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-dver")) {
		PARAM_CHECK(1);
		cia_.title_version = EsVersion::make_data_version(strtol(GET_PARAM(0), NULL, 0), EsVersion::get_build(cia_.title_version));

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-deviceid")) {
		PARAM_CHECK(1);
		cia_.device_id = strtoul(GET_PARAM(0), NULL, 16);

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-dlc")) {
		PARAM_CHECK(0);
		cia_.dlc_title = true;

		return SUCCESS_RET;
	}
	/*
	// TWL title conversion
	else if (MATCH_ARG("-srl")) {
		PARAM_CHECK(1);
		common_.input_path = GET_PARAM(0);
		common_.input_type = FILE_SRL;
		common_.output_type = FILE_CIA;

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-tad")) {
		PARAM_CHECK(1);
		common_.input_path = GET_PARAM(0);
		common_.input_type = FILE_TAD;
		common_.output_type = FILE_CIA;

		return SUCCESS_RET;
	}
	*/
	/*
	// CTR container conversion
	else if (MATCH_ARG("-ccitocia")) {
		PARAM_CHECK(1);
		common_.input_path = GET_PARAM(0);
		common_.input_type = FILE_CCI;
		common_.output_type = FILE_CIA;

		return SUCCESS_RET;
	}
	else if (MATCH_ARG("-ciatocci")) {
		PARAM_CHECK(1);
		common_.input_path = GET_PARAM(0);
		common_.input_type = FILE_CIA;
		common_.output_type = FILE_CCI;

		return SUCCESS_RET;
	}
	*/

	// content specify
	else if (MATCH_ARG("-content") || MATCH_ARG("-i")) {
		PARAM_CHECK(1);

		std::string content_str = GET_PARAM(0);
		sInputContentInfo content;
		size_t pos0 = content_str.find(':');
		size_t pos1 = content_str.find_last_of(':');

		// check for essential delimiter
		if (pos0 == std::string::npos) {
			fprintf(stderr, "[MAKEROM ERROR] Parameters for \"%s\" must be of the format:\n   For CCI: \"<path>:<index>\"\n   For CIA: \"<path>:<index>:<id>\"\n", GET_ARG);
			return FAIL_RET;
		}

		// separate path
		content.path = content_str.substr(0, pos0);

		// if there is only one delimiter, only the index is specified
		if (pos0 == pos1) {
			content.index = strtol(content_str.substr(pos0 + 1).c_str(), NULL, 0);
			content.id = 0xdeadbabe;
		}
		else {
			content.index = strtol(content_str.substr(pos0 + 1, pos1 - pos0 - 1).c_str(), NULL, 0);
			content.id = strtoul(content_str.substr(pos1 + 1).c_str(), NULL, 0);
		}

		// save to contents vector
		common_.contents.push_back(content);

		return SUCCESS_RET;
	}

	// -DNAME=VALUE or -DNAME VALUE
	else if (strncmp(GET_ARG, "-D", 2) == 0) {
		// validate that there are no more than 1 parameter
		if (arg_param_num > 1) {
			fprintf(stderr, "[MAKEROM ERROR] RSF string substitutions must be of the format:\n   \"-DNAME=VALUE\" or \"-DNAME VALUE\"\n");
			return FAIL_RET;
		}

sRsfStringSubstitute subs;

std::string tmp = GET_ARG;
size_t separater_pos = tmp.find('=', 0);

// if there is a parameter, it is the KEY, and should not have any '=' present in the NAME section
if (arg_param_num == 1) {
	if (separater_pos != std::string::npos) {
		fprintf(stderr, "[MAKEROM ERROR] RSF string substitutions must be of the format:\n   \"-DNAME=VALUE\" or \"-DNAME VALUE\"\n");
		return FAIL_RET;
	}
	subs.name = tmp.substr(2);
	subs.value = GET_PARAM(0);
}
// the the KEY is in the same string as the NAME, so we need to split before and after the '=' character
else {
	if (separater_pos == std::string::npos) {
		fprintf(stderr, "[MAKEROM ERROR] RSF string substitutions must be of the format:\n   \"-DNAME=VALUE\" or \"-DNAME VALUE\"\n");
		return FAIL_RET;
	}
	subs.name = tmp.substr(2, separater_pos - 2);
	subs.value = tmp.substr(separater_pos + 1);
}

common_.rsf_substitutes.push_back(subs);

return SUCCESS_RET;
	}
	else {
		fprintf(stderr, "[MAKEROM ERROR] Unrecognised argument \"%s\".\n", GET_ARG);
		return FAIL_RET;
	}

	return FAIL_RET;

#undef MATCH_PARAM
#undef GET_PARAM
#undef PARAM_CHECK
#undef MATCH_ARG
#undef GET_ARG
#undef FAIL_RET
#undef SUCCESS_RET
}

int UserSettings::PostProcessArguments()
{
	// if the output is a CIA/CCI file we need to organise the input content files
	if (common_.output_type == FILE_CIA || common_.output_type == FILE_CCI) {
		if (common_.contents.size() == 0) {
			fprintf(stderr, "[MAKEROM ERROR] When creating CIA/CCI files, you must specify content.\n");
			return ERR_INVALID_ARG;
		}

		// reorder the input content by index
		// this also discards duplicate inputs
		std::vector<sInputContentInfo> tmp;
		for (u32 i = 0; i < CiaHeader::kCiaMaxContentNum; i++) {
			for (auto& content : common_.contents) {
				if (content.index == i) {
					tmp.push_back(content);
					break;
				}
			}
		}
		common_.contents = tmp;

		// check colliding content ids
		for (size_t i = 0; i < common_.contents.size(); i++) {
			for (size_t j = i + 1; j < common_.contents.size(); j++) {
				if (common_.contents[i].id == common_.contents[j].id) {
					fprintf(stderr, "[MAKEROM ERROR] Content %d and content %d have the same id.\n", (u32)i, (u32)j);
					return ERR_INVALID_ARG;
				}
			}
		}

		// check for excession of maxium content
		if (common_.contents.size() > NcsdHeader::kSectionNum && common_.output_type == FILE_CCI) {
			fprintf(stderr, "[MAKEROM ERROR] When creating CCI files, you cannot specify more than %d content.\n", NcsdHeader::kSectionNum);
			return ERR_INVALID_ARG;
		}

		if (common_.contents.size() > CiaHeader::kCiaMaxContentNum && common_.output_type == FILE_CIA) {
			fprintf(stderr, "[MAKEROM ERROR] When creating CIA files, you cannot specify more than %d content.\n", CiaHeader::kCiaMaxContentNum);
			return ERR_INVALID_ARG;
		}

		ncch_.build_ncch = (common_.contents[0].index == 0) ? false : true;

	}

	if (ncch_.build_ncch) {
		// resolve ncch type
		if (ncch_.ncch_type == FILE_NCCH_GENERIC) {
			if (ncch_.elf_path.size() || ncch_.code_path.size() || ncch_.exheader_path.size()) {
				ncch_.ncch_type = FILE_CXI;
			}
			else {
				ncch_.ncch_type = FILE_CFA;
			}
		}

		// reflect ncch type in output if required
		if (common_.output_type == FILE_NCCH_GENERIC) {
			common_.output_type = ncch_.ncch_type;
		}

		if (common_.rsf_path.empty()) {
			fprintf(stderr, "[MAKEROM ERROR] When creating NCCH files, you must specify an RSF file.\n");
			return ERR_INVALID_ARG;
		}

		// check for essential input
		if (ncch_.ncch_type == FILE_CXI) {
			if (ncch_.elf_path.empty() && (ncch_.code_path.empty() || ncch_.exheader_path.empty())) {
				fprintf(stderr, "[MAKEROM ERROR] When creating CXI files, you must specify an ELF file.\n");
				return ERR_INVALID_ARG;
			}
			else if ((ncch_.code_path.empty() && !ncch_.exheader_path.empty()) || (!ncch_.code_path.empty() && ncch_.exheader_path.empty())) {
				fprintf(stderr, "[MAKEROM ERROR] When rebuilding CXI files, you must specify a code binary and exheader binary.\n");
				return ERR_INVALID_ARG;
			}

		}
	}

	return ERR_NOERROR;
}

const char* UserSettings::GetFileTypeExtention(FileType file_type)
{
	switch (file_type)
	{
	case (FILE_NCCH_GENERIC): return ".ncch";
	case (FILE_CXI): return ".cxi";
	case (FILE_CFA): return ".cfa";
	case (FILE_CCI): return ".cci";
	case (FILE_CIA): return ".cia";
	case (FILE_TIK): return ".tik";
	case (FILE_TMD): return ".tmd";
	case (FILE_SRL): return ".srl";
	case (FILE_TAD): return ".tad";
	default: ".bin";
	}
	return ".bin";
}

void UserSettings::ErrorInvalidParamNum(const char * arg, int valid_param_num)
{
	if (valid_param_num == 0) {
		fprintf(stderr, "[MAKEROM ERROR] Argument \"%s\" takes no parameters.\n", arg);
	}
	else if (valid_param_num == 1) {
		fprintf(stderr, "[MAKEROM ERROR] Argument \"%s\" takes 1 parameter.\n", arg);
	}
	else {
		fprintf(stderr, "[MAKEROM ERROR] Argument \"%s\" takes %d parameters.\n", arg, valid_param_num);
	}
}
