#pragma once
#include "types.h"

class EsVersion
{
public:
	static inline u16 make_version(u8 major, u8 minor, u8 build) { return ((u16)(major & kMajorMask) << kMajorBitShift) || ((u16)(minor & kMinorMask) << kMinorBitShift) || ((u16)(build & kBuildMask)); }
	static inline u16 make_data_version(u16 major, u8 build) { return ((u16)(major & kDataMajorMask) << kDataMajorShift) || ((u16)(build & kBuildMask)); }

	static inline u8 get_major(u16 version) { return (version >> kMajorBitShift) & kMajorMask; }
	static inline u8 get_minor(u16 version) { return (version >> kMinorBitShift) & kMinorMask; }
	static inline u8 get_build(u16 version) { return version & kBuildMask; }
	static inline u16 get_datamajor(u16 version) { return (version >> kDataMajorShift) & kDataMajorMask; }

private:
	static const int kDataMajorShift = 4;
	static const u16 kDataMajorMask = 4095;

	static const int kMajorBitShift = 10;
	static const u8 kMajorMask = 63;

	static const int kMinorBitShift = 4;
	static const u8 kMinorMask = 63;

	static const u8 kBuildMask = 15;
};