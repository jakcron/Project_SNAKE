#pragma once
#include "types.h"
#include "oschar.h"

class Smdh
{
public:
	static const int kNameLen = 0x40;
	static const int kDescriptionLen = 0x80;
	static const int kAuthorLen = 0x40;
	static const int kSmallIconSize = 24*24;
	static const int kLargeIconSize = 48*48;

	enum SmdhTitle
	{
		SMDH_TITLE_JAPANESE,
		SMDH_TITLE_ENGLISH,
		SMDH_TITLE_GERMAN,
		SMDH_TITLE_ITALIAN,
		SMDH_TITLE_SPANISH,
		SMDH_TITLE_SIMPLIFIED_CHINESE,
		SMDH_TITLE_KOREAN,
		SMDH_TITLE_DUTCH,
		SMDH_TITLE_PORTUGESE,
		SMDH_TITLE_RUSSIAN,
		SMDH_TITLE_TRADITIONAL_CHINESE
	};

	enum SmdhRegion
	{
		SMDH_REGION_JAPAN = BIT(0),
		SMDH_REGION_USA = BIT(1),
		SMDH_REGION_EUROPE = BIT(2),
		SMDH_REGION_AUSTRALIA = BIT(3),
		SMDH_REGION_CHINA = BIT(4),
		SMDH_REGION_TAIWAN = BIT(5),
		SMDH_REGION_KOREA = BIT(6),
		SMDH_REGION_ALL = 0xFFFFFFFF
	};

	enum SmdhRatingAgency
	{
		SMDH_RATING_AGENCY_CERO = 0,
		SMDH_RATING_AGENCY_ESRB = 1,
		SMDH_RATING_AGENCY_USK = 3,
		SMDH_RATING_AGENCY_PEGI_GEN = 4,
		SMDH_RATING_AGENCY_PEGI_PRT = 6,
		SMDH_RATING_AGENCY_PEGI_BBFC = 7,
		SMDH_RATING_AGENCY_COB = 8,
		SMDH_RATING_AGENCY_GRB = 9,
		SMDH_RATING_AGENCY_CGSRR = 10
	};

	enum SmdhAgeRatingFlag
	{
		SMDH_AGE_RATING_FLAG_NO_RESTRICTION = BIT(5),
		SMDH_AGE_RATING_FLAG_RATING_PENDING = BIT(6)
	};

	enum SmdhFlag
	{
		SMDH_FLAG_VISABLE = BIT(0),
		SMDH_FLAG_AUTOBOOT = BIT(1),
		SMDH_FLAG_USE_3D_EFFECT = BIT(2),
		SMDH_FLAG_AUTOSAVE_ON_EXIT = BIT(4),
		SMDH_FLAG_USE_EXTENDED_BANNER = BIT(5),
		SMDH_FLAG_USE_SAVE_DATA = BIT(7),
		SMDH_FLAG_RECORD_USAGE = BIT(8),
		SMDH_FLAG_DISABLE_SAVE_DATA_BACKUP = BIT(10),
		SMDH_FLAG_ENABLE_MIIVERSE_JUMP_ARGS = BIT(11),
		SMDH_FLAG_SNAKE_ONLY = BIT(12),
		SMDH_FLAG_DEPOSIT_SALE = BIT(13),
	};

	Smdh();
	~Smdh();

	inline const u8* data_blob() const { return (const u8*)& smdh_; }
	inline u32 data_size() const { return sizeof(struct sSmdh); }

	void SetTitle(SmdhTitle language, utf16char_t name[kNameLen], utf16char_t description[kDescriptionLen], utf16char_t author[kAuthorLen]);
	void SetRegionLockout(SmdhRegion region);
	void SetAgeRestriction(SmdhRatingAgency agency, u8 age, u8 flags);
	void SetFlag(u32 flags);
	void SetEulaVersion(u8 major, u8 minor);
	void SetMatchMakerId(u32 id, u64 bit_id);
	void SetStreetpassId(u32 id);
	void SetBannerDefaultFrame(float frame);
	void SetIconData(const u16 small_icon[kSmallIconSize], const u16 large_icon[kLargeIconSize]);
private:
	const char kMagic[4] = { 'S', 'M', 'D', 'H' };
	static const int kMaxTitleNum = 0x10;
	static const int kMaxAgeRestrictionNum = 0x10;

	enum SmdhAgeRatingPrivateFlag
	{
		SMDH_AGE_RATING_MASK = SMDH_AGE_RATING_FLAG_NO_RESTRICTION - 1,
		SMDH_AGE_RATING_FLAG_ENABLED = BIT(7)
	};

	enum SmdhPrivateFlag
	{
		SMDH_FLAG_REQUIRE_ACCEPT_EULA = BIT(3),
		SMDH_FLAG_REGION_RATING_USED = BIT(6),
	};

	struct sSmdh
	{
		char magic[4];
		u16 version;
		u8 reserved0[2];
		struct sTitle
		{
			utf16char_t name[kNameLen];
			utf16char_t description[kDescriptionLen];
			utf16char_t author[kAuthorLen];
		} titles[kMaxTitleNum];
		struct sSettings
		{
			u8 region_rating[kMaxAgeRestrictionNum];
			u32 region_lockout;
			u32 match_maker_id;
			u64 match_maker_bit_id;
			u32 flags;
			u8 reserved[2];
			u16 eula_version;
			u32 default_animation_frame;
			u32 streetpass_id;
		} settings;
		u8 reserved1[0x8];
		u16 small_icon[kSmallIconSize];
		u16 large_icon[kLargeIconSize];
	};

	struct sSmdh smdh_;
};