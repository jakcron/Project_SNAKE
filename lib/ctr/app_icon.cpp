#include "app_icon.h"



AppIcon::AppIcon()
{
}

AppIcon::AppIcon(const u8 * data)
{
	DeserialiseData(data);
}


AppIcon::~AppIcon()
{
}

const u8 * AppIcon::GetSerialisedData() const
{
	return serialised_data_.data_const();
}

size_t AppIcon::GetSerialisedDataSize() const
{
	return serialised_data_.size();
}

void AppIcon::SerialiseData()
{
	// allocate memory for serialised data
	if (serialised_data_.alloc(sizeof(sIcon)) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for serialised data");
	}

	// serialise data
	sIcon* icn = (sIcon*)serialised_data_.data();

	icn->set_struct_signature(kStructSignature);
	icn->set_version(kVersion);

	std::u16string tmp_str;
	for (size_t i = 0; i < kLanguageNum; i++)
	{
		tmp_str = std::u16string(titles_[i].name);
		MakeLittleEndian(tmp_str);
		icn->set_name((Language)i, tmp_str);

		tmp_str = std::u16string(titles_[i].description);
		MakeLittleEndian(tmp_str);
		icn->set_description((Language)i, tmp_str);

		tmp_str = std::u16string(titles_[i].author);
		MakeLittleEndian(tmp_str);
		icn->set_author((Language)i, tmp_str);
	}

	for (size_t i = 0; i < kAgeRestrictionNum; i++)
	{
		icn->set_age_rating((RatingAgency)i, age_rating_[i].status, age_rating_[i].age);
	}

	icn->set_region_lockout(region_lockout_);
	icn->set_match_maker_id(match_maker_id_);
	icn->set_match_maker_bit_id(match_maker_bit_id_);
	icn->set_flags(flags_);
	icn->set_eula_version(eula_version_.major, eula_version_.minor);
	icn->set_default_animation_frame(default_animation_frame_);
	icn->set_street_pass_id(street_pass_id_);

	std::vector<u16> tmp_vct;
	
	tmp_vct = std::vector<u16>(small_icon_);
	MakeLittleEndian(tmp_vct);
	icn->set_small_icon(tmp_vct.data());

	tmp_vct = std::vector<u16>(large_icon_);
	MakeLittleEndian(tmp_vct);
	icn->set_large_icon(tmp_vct.data());
}

void AppIcon::SetTitle(Language language, const std::u16string & name, const std::u16string & description, const std::u16string & author)
{
	if (language >= kLanguageNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal language ID\n");
	}

	if (name.length() > kNameLen)
	{
		throw ProjectSnakeException(kModuleName, "Title name too long");
	}

	if (description.length() > kDescriptionLen)
	{
		throw ProjectSnakeException(kModuleName, "Title description too long");
	}

	if (author.length() > kAuthorLen)
	{
		throw ProjectSnakeException(kModuleName, "Title author too long");
	}


	titles_[language].name = name;
	titles_[language].description = description;
	titles_[language].author = author;
}

void AppIcon::SetRegionLockout(u32 region_lockout)
{
	region_lockout_ = region_lockout;
}

void AppIcon::SetAgeRestriction(RatingAgency agency, u8 age, u8 flags)
{
	if (agency >= kAgeRestrictionNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal RatingAgency ID");
	}

	age_rating_[agency].status = flags;
	age_rating_[agency].age = age;
}

void AppIcon::SetFlag(u32 flags)
{
	flags_ = flags;
}

void AppIcon::EnableFlag(Flag flag)
{
	flags_ |= flag;
}

void AppIcon::DisableFlag(Flag flag)
{
	flags_ &= ~((u32)(flag));
}

void AppIcon::SetEulaVersion(u8 major, u8 minor)
{
	eula_version_.major = major;
	eula_version_.minor = minor;
}

void AppIcon::SetMatchMakerId(u32 id, u64 bit_id)
{
	match_maker_id_ = id;
	match_maker_bit_id_ = bit_id;
}

void AppIcon::SetBannerDefaultFrame(float frame)
{
	default_animation_frame_ = frame;
}

void AppIcon::SetStreetpassId(u32 id)
{
	street_pass_id_ = id;
}

void AppIcon::SetIconData(const std::vector<u16>& small_icon, const std::vector<u16>& large_icon)
{
	small_icon_ = small_icon;
	large_icon_ = large_icon;
}

void AppIcon::MakeLittleEndian(std::vector<u16>& in)
{
	for (size_t i = 0; i < in.size(); i++)
	{
		in[i] = le_hword(in[i]);
	}
}

void AppIcon::MakeLittleEndian(std::u16string& in)
{
	for (size_t i = 0; i < in.length(); i++)
	{
		in[i] = le_hword(in[i]);
	}
}

void AppIcon::ClearDeserialisedVariables()
{
	version_ = kVersion;
	for (size_t i = 0; i < kLanguageNum; i++)
	{
		titles_[i].name.clear();
		titles_[i].description.clear();
		titles_[i].author.clear();
	}
	for (size_t i = 0; i < kAgeRestrictionNum; i++)
	{
		age_rating_[i].status = (AgeRatingFlag)0;
		age_rating_[i].age = 0;
	}
	region_lockout_ = 0;
	match_maker_id_ = 0;
	match_maker_bit_id_ = 0;
	flags_ = 0;
	eula_version_.major = 0;
	eula_version_.minor = 0;
	default_animation_frame_ = 0;
	street_pass_id_ = 0;
	small_icon_.clear();
	large_icon_.clear();
}

void AppIcon::DeserialiseData(const u8 * data)
{
	ClearDeserialisedVariables();

	// save local copy of serialised data
	if (serialised_data_.alloc(sizeof(sIcon)) != MemoryBlob::ERR_NONE)
	{
		throw ProjectSnakeException(kModuleName, "Failed to allocate memory for deserialised data");
	}
	memcpy(serialised_data_.data(), data, sizeof(sIcon));

	// get pointer to header struct
	const sIcon* icn = (const sIcon*)serialised_data_.data_const();

	// check for corruption
	if (memcmp(icn->struct_signature(), kStructSignature, 4) != 0)
	{
		throw ProjectSnakeException(kModuleName, "Data is corrupt (invalid header signature)");
	}

	if (icn->version() != kVersion)
	{
		throw ProjectSnakeException(kModuleName, "Data is corrupt (invalid format version)");
	}

	// deserialise variables
	for (size_t i = 0; i < kLanguageNum; i++)
	{
		titles_[i].name = std::u16string(icn->name((Language)i), kNameLen);
		MakeLittleEndian(titles_[i].name);
		titles_[i].description = std::u16string(icn->description((Language)i), kDescriptionLen);
		MakeLittleEndian(titles_[i].description);
		titles_[i].author = std::u16string(icn->author((Language)i), kAuthorLen);
		MakeLittleEndian(titles_[i].author);
	}
	for (size_t i = 0; i < kAgeRestrictionNum; i++)
	{
		age_rating_[i].status = icn->age_rating_flags((RatingAgency)i);
		age_rating_[i].age = icn->age_rating((RatingAgency)i);
	}
	region_lockout_ = icn->region_lockout();
	match_maker_id_ = icn->match_maker_id();
	match_maker_bit_id_ = icn->match_maker_bit_id();
	flags_ = icn->flags();
	eula_version_.major = icn->eula_major();
	eula_version_.minor = icn->eula_minor();
	default_animation_frame_ = icn->default_animation_frame();
	street_pass_id_ = icn->street_pass_id();

	for (size_t i = 0; i < kSmallIconSize; i++)
	{
		small_icon_.push_back(le_word(icn->small_icon()[i]));
	}

	for (size_t i = 0; i < kLargeIconSize; i++)
	{
		large_icon_.push_back(le_word(icn->large_icon()[i]));
	}
}

const std::u16string & AppIcon::GetName(Language language) const
{
	if (language >= kLanguageNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal language ID\n");
	}

	return titles_[language].name;
}

const std::u16string & AppIcon::GetDescription(Language language) const
{
	if (language >= kLanguageNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal language ID\n");
	}

	return titles_[language].description;
}

const std::u16string & AppIcon::GetAuthor(Language language) const
{
	if (language >= kLanguageNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal language ID\n");
	}

	return titles_[language].author;
}

u32 AppIcon::GetRegionLockout() const
{
	return region_lockout_;
}

bool AppIcon::IsRegionAllowed(RegionLock region) const
{
	return (region_lockout_ & region) == region;
}

u8 AppIcon::GetAgeRestriction(RatingAgency agency)
{
	if (agency >= kAgeRestrictionNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal RatingAgency ID");
	}

	return age_rating_[agency].age;
}

bool AppIcon::IsAgeRestrictionExempt(RatingAgency agency)
{
	if (agency >= kAgeRestrictionNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal RatingAgency ID");
	}

	return (age_rating_[agency].status & AgeRatingFlag::FLAG_NO_RESTRICTION) == AgeRatingFlag::FLAG_NO_RESTRICTION;
}

bool AppIcon::IsAgeRestrictionPending(RatingAgency agency)
{
	if (agency >= kAgeRestrictionNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal RatingAgency ID");
	}

	return (age_rating_[agency].status & AgeRatingFlag::FLAG_RATING_PENDING) == AgeRatingFlag::FLAG_RATING_PENDING;
}

bool AppIcon::IsAgeRestrictionEnabled(RatingAgency agency)
{
	if (agency >= kAgeRestrictionNum)
	{
		throw ProjectSnakeException(kModuleName, "Illegal RatingAgency ID");
	}

	return (age_rating_[agency].status & AgeRatingFlag::FLAG_ENABLED) == AgeRatingFlag::FLAG_ENABLED;
}

u32 AppIcon::GetFlag() const
{
	return flags_;
}

bool AppIcon::IsFlagSet(Flag flag) const
{
	return (flags_ & flag) == flag;
}

u8 AppIcon::GetEulaMajor() const
{
	return eula_version_.major;
}

u8 AppIcon::GetEulaMinor() const
{
	return eula_version_.minor;
}

u32 AppIcon::GetMatchMakerId() const
{
	return match_maker_id_;
}

u64 AppIcon::GetMatchMakerBitId() const
{
	return match_maker_bit_id_;
}

float AppIcon::GetBannerDefaultFrame() const
{
	return default_animation_frame_;
}

u32 AppIcon::GetStreetPassId() const
{
	return street_pass_id_;
}

const std::vector<u16>& AppIcon::GetSmallIcon() const
{
	return small_icon_;
}

const std::vector<u16>& AppIcon::GetLargeIcon() const
{
	return large_icon_;
}
