#pragma once
#include "types.h"

class CtrAppIcon
{
public:
	static const int kSmallIconSize = 24 * 24;
	static const int kLargeIconSize = 48 * 48;

	CtrAppIcon();
	~CtrAppIcon();

	int CreateIcon(const char* png_path);

	inline const u16* icon24() const { return small_icon_; }
	inline const u16* icon48() const { return large_icon_; }
private:
	u16 small_icon_[kSmallIconSize];
	u16 large_icon_[kLargeIconSize];

	void ClearIconData();
	u16 PackColour(u8 r, u8 g, u8 b, u8 a);
	void GetTiledIconData(u16* out, u8* in, int height, int width);
};
