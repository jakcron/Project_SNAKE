#pragma once
#include <fnd/types.h>
#include <cstdint>

class ProgramId_v1 
{
public:
	enum DeviceType
	{
		DEVICE_CTR = 0x0004,
		DEVICE_CAFE = 0x0005
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
		ID_MASK = BIT(28)-1,
		ID_MASK_CTR = 0, // 3DS
		ID_MASK_CAFE = BIT(28), // WiiU
		ID_MASK_SNAKE = BIT(29) // n3DS
	};

	// deserialiser
	ProgramId_v1();
	ProgramId_v1(uint64_t program_id);
	void operator=(uint64_t program_id);
	uint64_t program_id();
	uint16_t device_type();
	uint16_t category();
	uint32_t unique_id();
	uint8_t variation();
	bool IsCategoryBitsSet(uint16_t bitmask);

	// static methods
	static inline uint64_t make_id(uint16_t device, uint16_t category, uint32_t unique_id, uint8_t variation)
	{
		return ((uint64_t)(device) << kDeviceTypeShift) | ((uint64_t)(category) << kCategoryShift) | ((unique_id & kUniqueIdMask) << kUniqueIdShift) | variation;
	}

	static inline uint64_t make_ctr_id(uint16_t category, uint32_t unique_id, uint8_t variation)
	{
		return make_id(DEVICE_CTR, category, (unique_id & ID_MASK) | ID_MASK_CTR, variation);
	}

	static inline uint64_t make_snake_id(uint16_t category, uint32_t unique_id, uint8_t variation)
	{
		return make_id(DEVICE_CTR, category, (unique_id & ID_MASK) | ID_MASK_SNAKE, variation);
	}

	static inline uint64_t make_cafe_id(uint16_t category, uint32_t unique_id, uint8_t variation)
	{
		return make_id(DEVICE_CAFE, category, (unique_id & ID_MASK) | ID_MASK_CAFE, variation);
	}

	static inline uint16_t get_device_type(uint64_t id)
	{
		return (id >> kDeviceTypeShift) & kDeviceTypeMask;
	}

	static inline uint16_t get_category(uint64_t id)
	{
		return (id >> kCategoryShift) & kCategoryMask;
	}

	static inline uint32_t get_unique_id(uint64_t id)
	{
		return (id >> kUniqueIdShift) & kUniqueIdMask;
	}

	static inline uint8_t get_variation(uint64_t id)
	{
		return (id >> kVariationShift) & kVariationMask;
	}

private:
	static const int kDeviceTypeShift = 48;
	static const uint16_t kDeviceTypeMask = 0xffff;
	static const int kCategoryShift = 32;
	static const uint16_t kCategoryMask = 0xffff;
	static const int kUniqueIdShift = 8;
	static const uint32_t kUniqueIdMask = 0xffffff;
	static const int kVariationShift = 0;
	static const uint8_t kVariationMask = 0xff;

	uint64_t program_id_;
};
