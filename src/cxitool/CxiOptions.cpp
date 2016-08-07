#include <algorithm>

#include "program_id.h"
#include "CxiOptions.h"
#include "YamlReader.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

CxiOptions::CxiOptions()
{
	SetDefaults();
}

CxiOptions::~CxiOptions()
{

}

int CxiOptions::EvaluateBooleanString(bool& dst, const std::string& str)
{
	if (str == "true")
	{
		dst = true;
	}
	else if (str == "false")
	{
		dst = false;
	}
	else
	{
		fprintf(stderr, "[ERROR] Invalid boolean string! %s\n", str.c_str());
		return 1;
	}
	return 0;
}

int CxiOptions::AddDependency(const std::string& dependency_str)
{
	u64 dependency_title_id = 0;

	if (dependency_str == "sm")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_SM, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "fs")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_FS, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "pm")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_PM, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "loader")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_LOADER, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "pxi")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_PXI, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "am")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_AM, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "camera")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_CAMERA, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "cfg")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_CONFIG, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "codec")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_CODEC, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "dmnt")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_DMNT, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "dsp")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_DSP, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "gpio")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_GPIO, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "gsp")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_GSP, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "hid")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_HID, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "i2c")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_I2C, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "mcu")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_MCU, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "mic")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_MIC, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "pdn")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_PDN, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "ptm")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_PTM, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "spi")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_SPI, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "ac")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_AC, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "cecd")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_CECD, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "csnd")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_CSND, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "dlp")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_DLP, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "http")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_HTTP, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "mp")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_MP, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "ndm")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_NDM, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "nim")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_NIM, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "nwm")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_NWM, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "socket")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_SOCKET, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "ssl")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_SSL, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "ps")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_PS, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "friends")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_FRIENDS, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "ir")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_IR, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "boss")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_BOSS, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "news")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_NEWS, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "debugger")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_DEBUGGER, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "ro")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_RO, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "act")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_ACT, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "nfc")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::MODULE_NFC, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "mvd")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::ID_MASK_N3DS | ProgramId::MODULE_MVD, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str == "qtm")
	{
		dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::ID_MASK_N3DS | ProgramId::MODULE_QTM, ProgramId::CORE_PRODUCTION);
	}
	else if (dependency_str.substr(0, 2) == "0x")
	{
		u64 id = strtoull(dependency_str.c_str(), 0, 16);

		if (id == 0)
		{
			die("[ERROR] Invalid dependency id: 0x0");
		}

		// the id is a full title id
		if (ProgramId::get_category(id) == ProgramId::CATEGORY_MODULE)
		{
			dependency_title_id = id;
		}

		// module unique ids are never larger than 0xff, so 
		if ((ProgramId::get_unique_id(id) & ~ProgramId::ID_MASK_N3DS) <= 0xff)
		{
			
			dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, id, ProgramId::CORE_PRODUCTION);
		}
		// otherwise this is a title id low
		else
		{
			dependency_title_id = ProgramId::make_ctr_id(ProgramId::CATEGORY_MODULE, ProgramId::get_unique_id(id), ProgramId::CORE_PRODUCTION);
		}
	}
	else
	{
		fprintf(stderr, "[ERROR] Unknown dependency: %s\n", dependency_str.c_str());
		return 1;
	}

	dependency_list_.push_back(dependency_title_id);
	return 0;
}

int CxiOptions::ParseSpecFileProccessConfig(YamlReader& spec)
{
	u32 level;
	std::vector<std::string> tmp(1);

	// move into children of ProcessConfig
	spec.GetEvent();

	// get level
	level = spec.level();

	while (spec.GetEvent() && spec.level() >= level)
	{
		if (!spec.is_event_scalar())
		{
			continue;
		}

		if (spec.event_string() == "IdealProcessor")
		{
			safe_call(spec.SaveValue(tmp[0]));
			ideal_processor_ = strtol(tmp[0].c_str(), NULL, 0);
		}
		else if (spec.event_string() == "AffinityMask")
		{
			safe_call(spec.SaveValue(tmp[0]));
			affinity_mask_ = strtol(tmp[0].c_str(), NULL, 0);
		}
		else if (spec.event_string() == "AppMemory")
		{
			safe_call(spec.SaveValue(tmp[0]));
			if (tmp[0] == "64MB")
			{
				system_mode_ = CxiExtendedHeader::SYSMODE_PROD;
			}
			else if (tmp[0] == "72MB")
			{
				system_mode_ = CxiExtendedHeader::SYSMODE_DEV3;
			}
			else if (tmp[0] == "80MB")
			{
				system_mode_ = CxiExtendedHeader::SYSMODE_DEV2;
			}
			else if (tmp[0] == "96MB")
			{
				system_mode_ = CxiExtendedHeader::SYSMODE_DEV1;
			}
			else
			{
				fprintf(stderr, "[ERROR] Invalid AppMemory: %s\n", tmp[0].c_str());
				return 1;
			}
		}
		else if (spec.event_string() == "SnakeAppMemory")
		{
			safe_call(spec.SaveValue(tmp[0]));
			if (tmp[0] == "Legacy")
			{
				system_mode_ext_ = CxiExtendedHeader::SYSMODE_SNAKE_LEGACY;
			}
			else if (tmp[0] == "124MB")
			{
				system_mode_ext_ = CxiExtendedHeader::SYSMODE_SNAKE_PROD;
			}
			else if (tmp[0] == "178MB")
			{
				system_mode_ext_ = CxiExtendedHeader::SYSMODE_SNAKE_DEV1;
			}
			else
			{
				fprintf(stderr, "[ERROR] Invalid SnakeAppMemory: %s\n", tmp[0].c_str());
				return 1;
			}
		}
		else if (spec.event_string() == "EnableL2Cache")
		{
			safe_call(spec.SaveValue(tmp[0]));
			safe_call(EvaluateBooleanString(enable_l2_cache_, tmp[0]));
		}
		else if (spec.event_string() == "Priority")
		{
			safe_call(spec.SaveValue(tmp[0]));
			priority_ = strtol(tmp[0].c_str(), NULL, 0);
		}
		else if (spec.event_string() == "SnakeCpuSpeed")
		{
			safe_call(spec.SaveValue(tmp[0]));
			if (tmp[0] == "268MHz")
			{
				cpu_speed_ = CxiExtendedHeader::CLOCK_268MHz;
			}
			else if (tmp[0] == "804MHz")
			{
				cpu_speed_ = CxiExtendedHeader::CLOCK_804MHz;
			}
			else
			{
				fprintf(stderr, "[ERROR] Invalid SnakeCpuSpeed: %s\n", tmp[0].c_str());
				return 1;
			}
		}
		else if (spec.event_string() == "Dependency")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				safe_call(AddDependency(tmp[i]));
			}
		}

		else
		{
			fprintf(stderr, "[ERROR] Unknown specfile key: ProcessConfig/%s\n", spec.event_string().c_str());
			return 1;
		}
	}

	return 0;
}

int CxiOptions::ParseSpecFileSaveData(YamlReader& spec)
{
	u32 level;
	std::vector<std::string> tmp(1);

	// move into children of SaveData
	spec.GetEvent();

	// get level
	level = spec.level();

	while (spec.GetEvent() && spec.level() >= level)
	{
		if (!spec.is_event_scalar())
		{
			continue;
		}

		if (spec.event_string() == "SaveDataSize")
		{
			safe_call(spec.SaveValue(tmp[0]));
			safe_call(SetSaveDataSize(tmp[0]));
		}
		else if (spec.event_string() == "SystemSaveIds")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				system_save_ids_.push_back(strtoul(tmp[i].c_str(), NULL, 0) & 0xffffffff);
			}
		}
		else if (spec.event_string() == "UseExtdata")
		{
			safe_call(spec.SaveValue(tmp[0]));
			safe_call(EvaluateBooleanString(use_extdata_, tmp[0]));
		}
		else if (spec.event_string() == "ExtDataId")
		{
			safe_call(spec.SaveValue(tmp[0]));
			extdata_id_ = strtoull(tmp[0].c_str(), NULL, 0);
		}
		else if (spec.event_string() == "UseOtherVariationSaveData")
		{
			safe_call(spec.SaveValue(tmp[0]));
			safe_call(EvaluateBooleanString(use_variation_save_, tmp[0]));
		}
		else if (spec.event_string() == "OtherUserSaveIds")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				other_user_save_ids_.push_back(strtoul(tmp[i].c_str(), NULL, 0) & 0xffffff);
			}
		}
		else if (spec.event_string() == "AccessibleSaveIds")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				accessible_save_ids_.push_back(strtoul(tmp[i].c_str(), NULL, 0) & 0xffffff);
			}
		}

		else
		{
			fprintf(stderr, "[ERROR] Unknown specfile key: SaveData/%s\n", spec.event_string().c_str());
			return 1;
		}
	}

	return 0;
}


int CxiOptions::SetSaveDataSize(std::string& size_str)
{
	// tolower string
	std::transform(size_str.begin(), size_str.end(), size_str.begin(), ::tolower);

	u32 raw_size = strtoul(size_str.c_str(), NULL, 0);

	if (size_str.find("k") != std::string::npos && (size_str.substr((size_str.find("k"))) == "k" || size_str.substr((size_str.find("k"))) == "kb"))
	{
		raw_size *= 0x400;
	}
	else if (size_str.find("m") != std::string::npos && (size_str.substr((size_str.find("m"))) == "m" || size_str.substr((size_str.find("m"))) == "mb"))
	{
		raw_size *= 0x400 * 0x400;
	}
	else
	{
		fprintf(stderr, "[ERROR] Invalid SaveDataSize: %s\n", size_str.c_str());
		return 1;
	}

	// check size alignment
	if (raw_size % (64 * 0x400) != 0)
	{
		die("[ERROR] SaveDataSize must be aligned to 64K");
	}

	save_data_size_ = raw_size;

	return 0;
}

int CxiOptions::ParseSpecFileRights(YamlReader& spec)
{
	u32 level;
	std::vector<std::string> tmp(1);

	// move into children of SaveData
	spec.GetEvent();

	// get level
	level = spec.level();

	while (spec.GetEvent() && spec.level() >= level)
	{
		if (!spec.is_event_scalar())
		{
			continue;
		}

		if (spec.event_string() == "Services")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				safe_call(AddService(tmp[i]));
			}
		}
		else if (spec.event_string() == "IORegisterMapping")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				safe_call(AddIOMapping(tmp[i]));
			}
		}
		else if (spec.event_string() == "MemoryMapping")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				safe_call(AddStaticMapping(tmp[i]));
			}
		}
		else if (spec.event_string() == "FSAccess")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				safe_call(AddFSAccessRight(tmp[i]));
			}
		}
		else if (spec.event_string() == "KernelFlag")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				safe_call(AddKernelFlag(tmp[i]));
			}
		}
		else if (spec.event_string() == "Arm9Access")
		{
			safe_call(spec.SaveValueSequence(tmp));
			for (int i = 0; i < tmp.size(); i++)
			{
				safe_call(AddArm9AccessRight(tmp[i]));
			}
		}

		else
		{
			fprintf(stderr, "[ERROR] Unknown specfile key: Rights/%s\n", spec.event_string().c_str());
			return 1;
		}
	}

	return 0;
}


int CxiOptions::AddService(const std::string& service_str)
{
	if (service_str.size() > 8)
	{
		fprintf(stderr, "[ERROR] Service name is too long: %s\n", service_str.c_str());
		return 1;
	}

	services_.push_back(service_str);

	return 0;
}

int CxiOptions::AddIOMapping(const std::string& mapping_str)
{
	std::string property;
	size_t pos1, pos2;
	CxiExtendedHeader::sMemoryMapping mapping;

	// get positions of '-' and ':'
	pos1 = mapping_str.find('-');
	pos2 = mapping_str.find(':');

	// check for invalid syntax
	// '-' shouldn't appear at the start
	// ':' shouldn't appear at all
	if (pos1 == 0 || pos2 != std::string::npos)
	{
		fprintf(stderr, "[ERROR] Invalid syntax in IORegisterMapping \"%s\"\n", mapping_str.c_str());
		return 1;
	}

	// npos means an end address wasn't specified, this is okay
	if (pos1 == std::string::npos)
	{
		mapping.start = strtoul(mapping_str.substr(0, pos2).c_str(), NULL, 16);
		mapping.end = 0;
	}
	// otherwise both start and end addresses should have been specified
	else
	{
		mapping.start = strtoul(mapping_str.substr(0, pos1).c_str(), NULL, 16);
		mapping.end = strtoul(mapping_str.substr(pos1 + 1).c_str(), NULL, 16);
	}

	if ((mapping.start & 0xfff) != 0x000)
	{
		fprintf(stderr, "[ERROR] %x in IORegisterMapping \"%s\" is not a valid start address\n", mapping.start, mapping_str.c_str());
		return 1;
	}

	if ((mapping.end & 0xfff) != 0xfff & mapping.end != 0)
	{
		fprintf(stderr, "[ERROR] %x in IORegisterMapping \"%s\" is not a valid end address\n", mapping.end, mapping_str.c_str());
		return 1;
	}

	io_mappings_.push_back(mapping);

	return 0;
}

int CxiOptions::AddStaticMapping(const std::string& mapping_str)
{
	std::string property("");
	size_t pos1, pos2;
	CxiExtendedHeader::sMemoryMapping mapping;

	// get positions of '-' and ':'
	pos1 = mapping_str.find('-');
	pos2 = mapping_str.find(':');

	if (pos2 != std::string::npos)
	{
		property = mapping_str.substr(pos2 + 1);
	}

	// check for invalid syntax
	// '-' or ':' shouldn't appear at the start
	// ':' shouldn't appear before '-'
	if (pos1 == 0 || pos2 == 0 || (pos2 < pos1 && pos1 != std::string::npos && pos2 != std::string::npos) || (pos2 != std::string::npos && property.empty()))
	{
		fprintf(stderr, "[ERROR] Invalid syntax in MemoryMapping \"%s\"\n", mapping_str.c_str());
		return 1;
	}

	// npos means an end address wasn't specified, this is okay
	if (pos1 == std::string::npos)
	{
		mapping.start = strtoul(mapping_str.substr(0, pos2).c_str(), NULL, 16);
		mapping.end = 0;
	}
	// otherwise both start and end addresses should have been specified
	else
	{
		mapping.start = strtoul(mapping_str.substr(0, pos1).c_str(), NULL, 16);
		mapping.end = strtoul(mapping_str.substr(pos1 + 1).c_str(), NULL, 16);
	}

	if ((mapping.start & 0xfff) != 0x000)
	{
		fprintf(stderr, "[ERROR] %x in MemoryMapping \"%s\" is not a valid start address\n", mapping.start, mapping_str.c_str());
		return 1;
	}

	if ((mapping.end & 0xfff) != 0xfff & mapping.end != 0)
	{
		fprintf(stderr, "[ERROR] %x in MemoryMapping \"%s\" is not a valid end address\n", mapping.end, mapping_str.c_str());
		return 1;
	}

	// the user has specified properties about the mapping
	if (property.size())
	{
		if (property == "r")
		{
			mapping.is_read_only = true;
		}
		else
		{
			fprintf(stderr, "[ERROR] %s in MemoryMapping \"%s\" is not a valid mapping property\n", property.c_str(), mapping_str.c_str());
			return 1;
		}
	}

	static_mappings_.push_back(mapping);

	return 0;
}

int CxiOptions::AddFSAccessRight(const std::string& right_str)
{
	if (right_str == "CategorySystemApplication")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CATEGORY_SYSTEM_APPLICATION;
	}
	else if (right_str == "CategoryHardwareCheck")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CATEGORY_HARDWARE_CHECK;
	}
	else if (right_str == "CategoryFileSystemTool")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CATEGORY_FILE_SYSTEM_TOOL;
	}
	else if (right_str == "Debug")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_DEBUG;
	}
	else if (right_str == "TwlCard" || right_str == "TwlCardBackup")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_TWL_CARD;
	}
	else if (right_str == "TwlNand" || right_str == "TwlNandData")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_TWL_NAND;
	}
	else if (right_str == "Boss")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_BOSS;
	}
	else if (right_str == "DirectSdmc" || right_str == "Sdmc")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_DIRECT_SDMC;
		arm9_fs_access_ |= CxiExtendedHeader::ARM9_USE_DIRECT_SDMC;
	}
	else if (right_str == "Core")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CORE;
	}
	else if (right_str == "CtrNandRo" || right_str == "NandRo")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CTR_NAND_RO;
	}
	else if (right_str == "CtrNandRw" || right_str == "NandRw")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CTR_NAND_RW;
	}
	else if (right_str == "CtrNandRoWrite" || right_str == "NandRoWrite")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CTR_NAND_RO_WRITE;
	}
	else if (right_str == "CategorySystemSettings")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CATEGORY_SYSTEM_SETTINGS;
	}
	else if (right_str == "Cardboard" || right_str == "SystemTransfer")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CARD_BOARD;
	}
	else if (right_str == "ExportInportIvs")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_EXPORT_IMPORT_IVS;
	}
	else if (right_str == "DirectSdmcWrite" || right_str == "SdmcWriteOnly")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_DIRECT_SDMC_WRITE;
	}
	else if (right_str == "SwitchCleanup")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_SWITCH_CLEANUP;
	}
	else if (right_str == "SaveDataMove")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_SAVE_DATA_MOVE;
	}
	else if (right_str == "Shop")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_SHOP;
	}
	else if (right_str == "Shell")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_SHELL;
	}
	else if (right_str == "CategoryHomeMenu")
	{
		arm11_fs_access_ |= CxiExtendedHeader::ARM11_CATEGORY_HOME_MENU;
	}
	else
	{
		fprintf(stderr, "[ERROR] Unknown FS Access right: %s\n", right_str.c_str());
		return 1;
	}

	return 0;
}

int CxiOptions::AddKernelFlag(const std::string& flag_str)
{
	if (flag_str == "PermitDebug")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_PERMIT_DEBUG;
	}
	else if (flag_str == "ForceDebug")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_FORCE_DEBUG;
	}
	else if (flag_str == "CanUseNonAlphaNum")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_CAN_USE_NON_ALPHABET_AND_NUMBER;
	}
	else if (flag_str == "CanWriteSharedPage")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_CAN_WRITE_SHARED_PAGE;
	}
	else if (flag_str == "CanUsePriviligedPriority")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_CAN_USE_PRIVILEGE_PRIORITY;
	}
	else if (flag_str == "PermitMainFunctionArgument")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_PERMIT_MAIN_FUNCTION_ARGUMENT;
	}
	else if (flag_str == "CanShareDeviceMemory")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_CAN_SHARE_DEVICE_MEMORY;
	}
	else if (flag_str == "RunnableOnSleep")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_RUNNABLE_ON_SLEEP;
	}
	else if (flag_str == "SpecialMemoryLayout")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_SPECIAL_MEMORY_LAYOUT;
	}
	else if (flag_str == "CanAccessCore2")
	{
		kernel_flags_ |= CxiExtendedHeader::KERNFLAG_CAN_ACCESS_CORE2;
	}
	else
	{
		fprintf(stderr, "[ERROR] Unknown Kernel Flag: %s\n", flag_str.c_str());
		return 1;
	}

	return 0;
}

int CxiOptions::AddArm9AccessRight(const std::string& right_str)
{
	if (right_str == "MountNand")
	{
		arm9_fs_access_ |= CxiExtendedHeader::ARM9_FS_MOUNT_NAND;
	}
	else if (right_str == "MountNandROWrite")
	{
		arm9_fs_access_ |= CxiExtendedHeader::ARM9_FS_MOUNT_NAND_RO_WRITE;
	}
	else if (right_str == "MountTwlN")
	{
		arm9_fs_access_ |= CxiExtendedHeader::ARM9_FS_MOUNT_TWLN;
	}
	else if (right_str == "MountWNand")
	{
		arm9_fs_access_ |= CxiExtendedHeader::ARM9_FS_MOUNT_WNAND;
	}
	else if (right_str == "MountCardSpi")
	{
		arm9_fs_access_ |= CxiExtendedHeader::ARM9_FS_MOUNT_CARD_SPI;
	}
	else if (right_str == "UseSDIF3")
	{
		arm9_fs_access_ |= CxiExtendedHeader::ARM9_USE_SDIF3;
	}
	else if (right_str == "CreateSeed")
	{
		arm9_fs_access_ |= CxiExtendedHeader::ARM9_CREATE_SEED;
	}
	else if (right_str == "UseCardSpi")
	{
		arm9_fs_access_ |= CxiExtendedHeader::ARM9_USE_CARD_SPI;
	}
	else
	{
		fprintf(stderr, "[ERROR] Unknown Arm9 Access right: %s\n", right_str.c_str());
		return 1;
	}

	return 0;
}

int CxiOptions::ParseSpecFile(const char* spec_file)
{
	YamlReader spec;
	u32 level;


	safe_call(spec.LoadFile(spec_file));

	level = spec.level();
	while (spec.GetEvent() && spec.level() == level)
	{
		if (!spec.is_event_scalar())
		{
			continue;
		}

		if (spec.event_string() == "ProcessConfig")
		{
			safe_call(ParseSpecFileProccessConfig(spec));
		}
		else if (spec.event_string() == "SaveData")
		{
			safe_call(ParseSpecFileSaveData(spec));
		}
		else if (spec.event_string() == "Rights")
		{
			safe_call(ParseSpecFileRights(spec));
		}
		else
		{
			fprintf(stderr, "[ERROR] Unknown specfile key: %s\n", spec.event_string().c_str());
			return 1;
		}
	}

	return spec.is_error() ? 1 : 0;
}

void CxiOptions::SetProductCode(const char* product_code)
{
	strncpy(product_code_, product_code, 16);
}

void CxiOptions::SetMakerCode(const char* maker_code)
{
	strncpy(maker_code_, maker_code, 2);
}

void CxiOptions::SetTitleId(u64 title_id)
{
	title_id_ = title_id;
}

void CxiOptions::SetProgramId(u64 program_id)
{
	program_id_ = program_id;
}

void CxiOptions::SetAppTitle(const char* app_title)
{
	strncpy(app_title_, app_title, 8);
}

void CxiOptions::SetIsCompressCode(bool compress)
{
	is_compressed_code_ = compress;
}

void CxiOptions::SetIsSdmcTitle(bool sdmc_title)
{
	is_sdmc_title_ = sdmc_title;
}

void CxiOptions::SetRemasterVersion(u16 version)
{
	remaster_version_ = version;
}

void CxiOptions::SetStackSize(u32 size)
{
	stack_size_ = size;
}

void CxiOptions::SetSaveDataSize(u32 size)
{
	save_data_size_ = size;
}

void CxiOptions::SetJumpId(u64 jump_id)
{
	jump_id_ = jump_id;
}

int CxiOptions::SetDependencies(const std::vector<u64>& ids)
{
	for (size_t i = 0; i < ids.size(); i++)
	{
		safe_call(AddDependency(ids[i]));
	}

	return 0;
}

int CxiOptions::AddDependency(u64 title_id)
{
	if (dependency_list_.size() > CxiExtendedHeader::De)
}

void CxiOptions::SetFirmwareTitleId(u64 title_id)
{
	firmware_title_id_ = title_id;
}

void CxiOptions::SetDefaults()
{
	strncpy(product_code_, "CTR-P-CTAP", 16);
	strncpy(app_title_, "CtrApp", 8);
	strncpy(maker_code_, "01", 2);
	title_id_ = 0x000400000ff3ff00;
	program_id_ = title_id_;
	jump_id_ = title_id_;

	is_sdmc_title_ = true;
	is_compressed_code_ = false;
	remaster_version_ = 0;
	stack_size_ = 0x4000;

	firmware_title_id_ = 0x0004013800000002;
	arm11_fs_access_ = 0;
	max_cpu_ = 0;
	resource_limit_category_ = CxiExtendedHeader::RESLIMIT_APPLICATION;

	memory_type_ = CxiExtendedHeader::MEMTYPE_APPLICATION;

	// enable system calls 0x00-0x7D
	for (int i = 0; i <= 0x7D; i++)
	{
		svc_calls_.push_back(i);
	}

	handle_table_size_ = 0x200;
	kernel_flags_ = 0;
	// fw 2.0.0
	min_kernel_version_[0] = 2;
	min_kernel_version_[1] = 29;

	arm9_fs_access_ = CxiExtendedHeader::ARM9_SD_APPLICATION;
	desc_version_ = 2;
}
