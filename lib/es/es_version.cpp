#include "es_version.h"

ESVersion::ESVersion(u16 version)
{
	version_ = version;
}

u16 ESVersion::version()
{
	return version_;
}

u8 ESVersion::major()
{
	return get_major(version_);
}

u8 ESVersion::minor()
{
	return get_minor(version_);
}

u8 ESVersion::build()
{
	return get_build(version_);
}

u16 ESVersion::data_version()
{
	return get_datamajor(version_);
}
