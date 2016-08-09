#include "smdh.h"

Smdh::Smdh()
{
	memset((u8*)&smdh_, 0, sizeof(struct sSmdh));
	memcpy(smdh_.magic, kMagic, 4);
	smdh_.version = 0;
}

Smdh::~Smdh()
{

}

void Smdh::SetTitle(SmdhTitle language, utf16char_t name[kNameLen], utf16char_t description[kDescriptionLen], utf16char_t author[kAuthorLen])
{
	u32 i;

	if (language >= kMaxTitleNum) return;

	// name
	for (i = 0; i < kNameLen && name[i] != 0; i++)
	{
		smdh_.titles[language].name[i] = le_hword(name[i]);
	}
	for (; i < kNameLen; i++)
	{
		smdh_.titles[language].name[i] = 0;
	}

	// description
	for (i = 0; i < kDescriptionLen && description[i] != 0; i++)
	{
		smdh_.titles[language].description[i] = le_hword(description[i]);
	}
	for (; i < kDescriptionLen; i++)
	{
		smdh_.titles[language].description[i] = 0;
	}

	// author
	for (i = 0; i < kAuthorLen && author[i] != 0; i++)
	{
		smdh_.titles[language].author[i] = le_hword(author[i]);
	}
	for (; i < kAuthorLen; i++)
	{
		smdh_.titles[language].author[i] = 0;
	}
}

void Smdh::SetRegionLockout(SmdhRegion region)
{
	smdh_.settings.region_lockout = le_word(region);
}

void Smdh::SetAgeRestriction(SmdhRatingAgency agency, u8 age, u8 flags)
{
	if (agency >= kMaxAgeRestrictionNum) return;

	smdh_.settings.flags |= SMDH_FLAG_REGION_RATING_USED;

	smdh_.settings.region_rating[agency] = (age & SMDH_AGE_RATING_MASK) | SMDH_AGE_RATING_FLAG_ENABLED | flags;
}

void Smdh::SetFlag(u32 flags)
{
	smdh_.settings.flags |= flags;
}

void Smdh::SetEulaVersion(u8 major, u8 minor)
{
	if (major == 0 && minor == 0)
	{
		smdh_.settings.flags &= ~SMDH_FLAG_REQUIRE_ACCEPT_EULA;
		smdh_.settings.eula_version = 0;
		return;
	}

	smdh_.settings.flags |= SMDH_FLAG_REQUIRE_ACCEPT_EULA;

	smdh_.settings.eula_version = le_hword((major << 8) | minor);
}

void Smdh::SetMatchMakerId(u32 id, u64 bit_id)
{
	smdh_.settings.match_maker_id = le_word(id);
	smdh_.settings.match_maker_bit_id = le_dword(bit_id);
}

void Smdh::SetStreetpassId(u32 id)
{
	smdh_.settings.streetpass_id = le_word(id);
}

void Smdh::SetBannerDefaultFrame(float frame)
{
	float tmp0 = frame;

	smdh_.settings.default_animation_frame = le_word(*(u32*)((void*)(&tmp0)));
}

void Smdh::SetIconData(const u16 small_icon[kSmallIconSize], const u16 large_icon[kLargeIconSize])
{
	for (int i = 0; i < kSmallIconSize; i++)
	{
		smdh_.small_icon[i] = le_hword(small_icon[i]);
	}
	for (int i = 0; i < kLargeIconSize; i++)
	{
		smdh_.large_icon[i] = le_hword(large_icon[i]);
	}
}
