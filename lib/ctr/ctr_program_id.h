#pragma once
#include <fnd/program_id_v1.h>

class CtrProgramId : public ProgramId_v1
{
public:
	enum ModuleIds
	{
		MODULE_SM = 0x10,
		MODULE_FS = 0x11,
		MODULE_PM = 0x12,
		MODULE_LOADER = 0x13,
		MODULE_PXI = 0x14,
		MODULE_AM = 0x15,
		MODULE_CAMERA = 0x16,
		MODULE_CONFIG = 0x17,
		MODULE_CODEC = 0x18,
		MODULE_DMNT = 0x19,
		MODULE_DSP = 0x1A,
		MODULE_GPIO = 0x1B,
		MODULE_GSP = 0x1C,
		MODULE_HID = 0x1D,
		MODULE_I2C = 0x1E,
		MODULE_MCU = 0x1F,
		MODULE_MIC = 0x20,
		MODULE_PDN = 0x21,
		MODULE_PTM = 0x22,
		MODULE_SPI = 0x23,
		MODULE_AC = 0x24,
		MODULE_CECD = 0x26,
		MODULE_CSND = 0x27,
		MODULE_DLP = 0x28,
		MODULE_HTTP = 0x29,
		MODULE_MP = 0x2A,
		MODULE_NDM = 0x2B,
		MODULE_NIM = 0x2C,
		MODULE_NWM = 0x2D,
		MODULE_SOCKET = 0x2E,
		MODULE_SSL = 0x2F,
		MODULE_PROC9 = 0x30,
		MODULE_PS = 0x31,
		MODULE_FRIENDS = 0x32,
		MODULE_IR = 0x33,
		MODULE_BOSS = 0x34,
		MODULE_NEWS = 0x35,
		MODULE_DEBUGGER = 0x36,
		MODULE_RO = 0x37,
		MODULE_ACT = 0x38,
		MODULE_NFC = 0x40,
		MODULE_MVD = 0x41,
		MODULE_QTM = 0x42
	};

	enum FirmwareIds
	{
		FIRMWARE_NATIVE = 0x00,
		FIRMWARE_TWL = 0x01,
		FIRMWARE_AGB = 0x02,
	};

	enum CoreVersionIds
	{
		CORE_SYSUPDATER = 0x01,
		CORE_PRODUCTION = 0x02,
		CORE_SAFEMODE = 0x03
	};

	CtrProgramId() : ProgramId_v1() {}
	CtrProgramId(uint64_t program_id) : ProgramId_v1(program_id) {}
	void operator=(uint64_t program_id) { ProgramId_v1::operator=(program_id); }
};