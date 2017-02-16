#pragma once
#include <fnd/types.h>
#include <fnd/memory_blob.h>

class AppIcon
{
public:
	// Public Enums
	enum Language
	{
		JAPANESE,
		ENGLISH,
		GERMAN,
		ITALIAN,
		SPANISH,
		SIMPLIFIED_CHINESE,
		KOREAN,
		DUTCH,
		PORTUGESE,
		RUSSIAN,
		TRADITIONAL_CHINESE
	};

	enum RegionLock
	{
		JAPAN = BIT(0),
		USA = BIT(1),
		EUROPE = BIT(2),
		AUSTRALIA = BIT(3),
		CHINA = BIT(4),
		TAIWAN = BIT(5),
		KOREA = BIT(6),
		ALL = 0x7FFFFFFF,
	};

	enum RatingAgency
	{
		CERO = 0,
		ESRB = 1,
		USK = 3,
		PEGI_GEN = 4,
		PEGI_PRT = 6,
		PEGI_BBFC = 7,
		COB = 8,
		GRB = 9,
		CGSRR = 10
	};

	enum AgeRatingFlag
	{
		FLAG_NO_RESTRICTION = BIT(5),
		FLAG_RATING_PENDING = BIT(6),
		FLAG_ENABLED = BIT(7),
		AGE_MASK = FLAG_NO_RESTRICTION - 1,
		FLAG_MASK = ~(u8)(AGE_MASK),
	};

	enum Flag
	{
		VISABLE = BIT(0),
		AUTOBOOT = BIT(1),
		USE_3D_EFFECT = BIT(2),
		REQUIRE_ACCEPT_EULA = BIT(3),
		AUTOSAVE_ON_EXIT = BIT(4),
		USE_EXTENDED_BANNER = BIT(5),
		RATING_USED = BIT(6),
		USE_SAVE_DATA = BIT(7),
		RECORD_USAGE = BIT(8),
		DISABLE_SAVE_DATA_BACKUP = BIT(10),
		ENABLE_MIIVERSE_JUMP_ARGS = BIT(11),
		SNAKE_ONLY = BIT(12),
		DEPOSIT_SALE = BIT(13)
	};

	// Public Constants
	static const size_t kNameLen = 0x40;
	static const size_t kDescriptionLen = 0x80;
	static const size_t kAuthorLen = 0x40;
	static const size_t kSmallIconSize = 24 * 24;
	static const size_t kLargeIconSize = 48 * 48;


	// Constructor/Destructor
	AppIcon();
	AppIcon(const u8* data);
	~AppIcon();

	// Export serialised data
	const u8* GetSerialisedData() const;
	size_t GetSerialisedDataSize() const;

	// Data Serialisation
	void SerialiseData();
	void SetTitle(Language language, const std::u16string& name, const std::u16string& description, const std::u16string& author);
	void SetRegionLockout(u32 region_lock);
	void SetAgeRestriction(RatingAgency agency, u8 age, u8 flags);
	void SetFlag(u32 flags);
	void EnableFlag(Flag flag);
	void DisableFlag(Flag flag);
	void SetEulaVersion(u8 major, u8 minor);
	void SetMatchMakerId(u32 id, u64 bit_id);
	void SetBannerDefaultFrame(float frame);
	void SetStreetpassId(u32 id);
	void SetIconData(const std::vector<u16>& small_icon, const std::vector<u16>& large_icon);

	// Data Deserialisation
	void DeserialiseData(const u8* data);
	const std::u16string& GetName(Language language) const;
	const std::u16string& GetDescription(Language language) const;
	const std::u16string& GetAuthor(Language language) const;
	u32 GetRegionLockout() const;
	bool IsRegionAllowed(RegionLock region) const;
	u8 GetAgeRestriction(RatingAgency agency);
	bool IsAgeRestrictionExempt(RatingAgency agency);
	bool IsAgeRestrictionPending(RatingAgency agency);
	bool IsAgeRestrictionEnabled(RatingAgency agency);
	u32 GetFlag() const;
	bool IsFlagSet(Flag flag) const;
	u8 GetEulaMajor() const;
	u8 GetEulaMinor() const;
	u32 GetMatchMakerId() const;
	u64 GetMatchMakerBitId() const;
	float GetBannerDefaultFrame() const;
	u32 GetStreetPassId() const;
	const std::vector<u16>& GetSmallIcon() const;
	const std::vector<u16>& GetLargeIcon() const;

private:
	const std::string kModuleName = "APP_ICON";
	const char kStructSignature[4] = { 'S', 'M', 'D', 'H' };
	static const u16 kVersion = 0;
	static const size_t kLanguageNum = 0x10;
	static const size_t kAgeRestrictionNum = 0x10;

	// Private Structures
#pragma pack (push, 1)
	struct sIcon
	{
	private:
		char struct_signature_[4];
		u16 version_;
		u8 reserved0[2];
		struct sTitle
		{
			char16_t name[kNameLen];
			char16_t description[kDescriptionLen];
			char16_t author[kAuthorLen];
		} titles_[kLanguageNum];
		struct sSettings
		{
			u8 rating[kAgeRestrictionNum];
			u32 region_lockout;
			u32 match_maker_id;
			u64 match_maker_bit_id;
			u32 flags;
			u8 eula_version[2];
			u8 reserved[2];
			u32 default_animation_frame;
			u32 street_pass_id;
		} settings_;
		u8 reserved1[0x8];
		u16 small_icon_[kSmallIconSize];
		u16 large_icon_[kLargeIconSize];
	public:
		const char* struct_signature() const { return struct_signature_; }
		u16 version() const { return le_hword(version_); }
		const char16_t* name(Language lang) const { return titles_[lang].name; }
		const char16_t* description(Language lang) const { return titles_[lang].description; }
		const char16_t* author(Language lang) const { return titles_[lang].author; }
		u8 age_rating(RatingAgency agency) const { return settings_.rating[agency] & AgeRatingFlag::AGE_MASK; }
		u8 age_rating_flags(RatingAgency agency) const { return settings_.rating[agency] & AgeRatingFlag::FLAG_MASK; }
		u32 region_lockout() const { return le_word(settings_.region_lockout); }
		u32 match_maker_id() const { return le_word(settings_.match_maker_id); }
		u64 match_maker_bit_id() const { return le_dword(settings_.match_maker_bit_id); }
		u32 flags() const { return le_word(settings_.flags); }
		u8 eula_major() const { return settings_.eula_version[1]; }
		u8 eula_minor() const { return settings_.eula_version[0]; }
		float default_animation_frame() const { u32 raw = le_word(settings_.default_animation_frame); return *(float*)((void*)(&raw)); } // casts be crazy: get address of variable(&) -> cast as void* -> cast as float* -> get variable at address(*)
		u32 street_pass_id() const { return le_word(settings_.street_pass_id); }
		const u16* small_icon() const { return small_icon_; }
		const u16* large_icon() const { return large_icon_; }

		void clear() { memset(this, 0, sizeof(*this)); }

		void set_struct_signature(const char* signature) { strncpy(struct_signature_, signature, 4); }
		void set_version(u16 version) { version_ = le_hword(version); }
		void set_name(Language lang, const std::u16string& name) { for (size_t i = 0; i < name.length() && i < kNameLen; i++) { titles_[lang].name[i] = name[i]; } }
		void set_description(Language lang, const std::u16string& description) { for (size_t i = 0; i < description.length() && i < kNameLen; i++) { titles_[lang].description[i] = description[i]; } }
		void set_author(Language lang, const std::u16string& author) { for (size_t i = 0; i < author.length() && i < kNameLen; i++) { titles_[lang].author[i] = author[i]; } }
		void set_age_rating(RatingAgency agency, u8 flags, u8 age) { settings_.rating[agency] = (flags & AgeRatingFlag::FLAG_MASK) | (age & AgeRatingFlag::AGE_MASK); }
		void set_region_lockout(u32 lockout) { settings_.region_lockout = le_word(lockout); }
		void set_match_maker_id(u32 id) { settings_.match_maker_id = le_word(id); }
		void set_match_maker_bit_id(u64 id) { settings_.match_maker_bit_id = le_dword(id); }
		void set_flags(u32 flags) { settings_.flags = le_word(flags); }
		void set_eula_version(u8 major, u8 minor) { settings_.eula_version[1] = major; settings_.eula_version[0] = minor; }
		void set_default_animation_frame(float frame) { settings_.default_animation_frame = le_word(*(u32*)((void*)(&frame))); }
		void set_street_pass_id(u32 id) { settings_.street_pass_id = le_word(id); }
		void set_small_icon(const u16* data) { for (size_t i = 0; i < kSmallIconSize; i++) { small_icon_[i] = data[i]; } }
		void set_large_icon(const u16* data) { for (size_t i = 0; i < kLargeIconSize; i++) { large_icon_[i] = data[i]; } }
	};
#pragma pack (pop)

	// serialised data
	MemoryBlob serialised_data_;

	// variables
	u16 version_;
	struct sAppTitle
	{
		std::u16string name;
		std::u16string description;
		std::u16string author;
	} titles_[kLanguageNum];
	struct sAgeRating
	{
		u8 status;
		u8 age;
	} age_rating_[kAgeRestrictionNum];
	u32 region_lockout_;
	u32 match_maker_id_;
	u64 match_maker_bit_id_;
	u32 flags_;
	struct sEulaVersion
	{
		u8 major;
		u8 minor;
	} eula_version_;
	float default_animation_frame_;
	u32 street_pass_id_;
	std::vector<u16> small_icon_;
	std::vector<u16> large_icon_;

	// create a wordorder switcher for icon data and strings
	void MakeLittleEndian(std::vector<u16>& in);
	void MakeLittleEndian(std::u16string& in);

	void ClearDeserialisedVariables();
};

