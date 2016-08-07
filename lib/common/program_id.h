#pragma once
#include "types.h"
#include <cstdint>

class ProgramId 
{
public:
	enum DeviceType
	{
		DEVICE_CTR = 0x0004,
		DEVICE_WUP = 0x0005
	};

	enum CategoryFlag
	{
		CATEGORY_FLAG_NORMAL = 0,
		CATEGORY_FLAG_DLP_CHILD = BIT(0),
		CATEGORY_FLAG_DEMO = BIT(1),
		CATEGORY_FLAG_CONTENTS = BIT(0) | BIT(1),
		CATEGORY_FLAG_ADD_ON_CONTENTS = BIT(2),
		CATEGORY_FLAG_PATCH = BIT(1) | BIT(2),
		CATEGORY_FLAG_NOT_EXECUTABLE = BIT(3),
		CATEGORY_FLAG_SYSTEM = BIT(4),
		CATEGORY_FLAG_REQUIRE_BATCH_UPDATE = BIT(5),
		CATEGORY_FLAG_NOT_REQUIRE_USER_APPROVAL = BIT(6),
		CATEGORY_FLAG_NOT_REQUIRE_RIGHT_FOR_MOUNT = BIT(7),
		CATEGORY_FLAG_CAN_SKIP_CONVERT_JUMP_ID = BIT(8),
		CATEGORY_FLAG_TWL_TITLE = BIT(15),
	};

	enum CategoryType
	{
		CATEGORY_APPLICATION			= ( CATEGORY_FLAG_NORMAL ),
		CATEGORY_DLP_CHILD				= ( CATEGORY_FLAG_DLP_CHILD ),
		CATEGORY_DEMO					= ( CATEGORY_FLAG_DEMO ),
		CATEGORY_CONTENTS				= ( CATEGORY_FLAG_CONTENTS ),
		CATEGORY_PATCH					= ( CATEGORY_FLAG_PATCH |
											CATEGORY_FLAG_NOT_EXECUTABLE ),
		CATEGORY_ADD_ON_CONTENTS		= ( CATEGORY_FLAG_ADD_ON_CONTENTS |
											CATEGORY_FLAG_NOT_EXECUTABLE |
											CATEGORY_FLAG_NOT_REQUIRE_RIGHT_FOR_MOUNT ),
		CATEGORY_FIRMWARE				= ( CATEGORY_FLAG_SYSTEM |
											CATEGORY_FLAG_NOT_EXECUTABLE |
											CATEGORY_FLAG_REQUIRE_BATCH_UPDATE |
											CATEGORY_FLAG_CAN_SKIP_CONVERT_JUMP_ID ),
		CATEGORY_MODULE					= ( CATEGORY_FLAG_SYSTEM |
											CATEGORY_FLAG_REQUIRE_BATCH_UPDATE |
											CATEGORY_FLAG_CAN_SKIP_CONVERT_JUMP_ID ),
		CATEGORY_APPLET					= ( CATEGORY_FLAG_SYSTEM |
											CATEGORY_FLAG_REQUIRE_BATCH_UPDATE ),
		CATEGORY_SYSTEM_APPLICATION		= (	CATEGORY_FLAG_SYSTEM ),
		CATEGORY_SYSTEM_CONTENT			= ( CATEGORY_FLAG_SYSTEM |
											CATEGORY_FLAG_CONTENTS |
											CATEGORY_FLAG_NOT_EXECUTABLE ),
		CATEGORY_SHARED_CONTENT			= ( CATEGORY_FLAG_SYSTEM |
											CATEGORY_FLAG_CONTENTS |
											CATEGORY_FLAG_NOT_EXECUTABLE |
											CATEGORY_FLAG_NOT_REQUIRE_RIGHT_FOR_MOUNT ),
		CATEGORY_AUTO_UPDATE_CONTENT	= ( CATEGORY_FLAG_SYSTEM |
											CATEGORY_FLAG_CONTENTS |
											CATEGORY_FLAG_NOT_EXECUTABLE |
											CATEGORY_FLAG_NOT_REQUIRE_RIGHT_FOR_MOUNT |
											CATEGORY_FLAG_NOT_REQUIRE_USER_APPROVAL),
	};

	enum UniqueIdDeviceMask
	{
		ID_MASK_N3DS = BIT(29)
	};

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

	static inline uint64_t make_id(uint16_t device, uint16_t category, uint32_t unique_id, uint8_t variation)
	{
		return ((u64)(device) << 48) | ((u64)(category) << 32) | ((unique_id & 0xFFFFFF) << 8) | variation;
	}

	static inline uint64_t make_ctr_id(uint16_t category, uint32_t unique_id, uint8_t variation)
	{
		return make_id(DEVICE_CTR, category, unique_id, variation);
	}

	static inline uint64_t make_snake_id(uint16_t category, uint32_t unique_id, uint8_t variation)
	{
		return make_ctr_id(category, (unique_id & 0xfffff) | UniqueIdDeviceMask::ID_MASK_N3DS, variation);
	}

	static inline uint16_t get_device_type(uint64_t id)
	{
		return (id >> 48) & 0xffff;
	}

	static inline uint16_t get_category(uint64_t id)
	{
		return (id >> 32) & 0xffff;
	}

	static inline uint32_t get_unique_id(uint64_t id)
	{
		return (id >> 8) & 0xffffff;
	}

	static inline uint8_t get_variation(uint64_t id)
	{
		return (id >> 0) & 0xff;
	}
};
