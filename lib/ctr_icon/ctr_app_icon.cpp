#include "ctr_app_icon.h"
#include "bannerutil/stb_image.h"

#define die(msg) do { fputs(msg "\n\n", stderr); return 1; } while(0)
#define safe_call(a) do { int rc = a; if(rc != 0) return rc; } while(0)

CtrAppIcon::CtrAppIcon()
{
	ClearIconData();
}

CtrAppIcon::~CtrAppIcon()
{
	ClearIconData();
}

int CtrAppIcon::CreateIcon(const char* png_path)
{
	int img_width, img_height, img_depth;
	u8 *img_48_data;
	u8 img_24_data[24 * 24 * 4] = { 0 };
	int i[4], id;
	u8 r[4], g[4], b[4], a[4];

	ClearIconData();

	// get large icon
	if ((img_48_data = stbi_load(png_path, &img_width, &img_height, &img_depth, STBI_rgb_alpha)) == NULL)
	{
		fprintf(stderr, "[ERROR] Failed to decode image. (%s)\n", stbi_failure_reason());
		return 1;
	}

	if (img_width != 48 || img_height != 48 || img_depth != STBI_rgb_alpha)
	{
		die("[ERROR] Decoded image has invalid properties.");
	}

	GetTiledIconData(large_icon_, img_48_data, 48, 48);

	// get small icon from large icon
	
	for (int y = 0; y < img_height; y += 2) {
		for (int x = 0; x < img_width; x += 2) {
			i[0] = (y * 48 + x) * 4;
			r[0] = img_48_data[i[0] + 0];
			g[0] = img_48_data[i[0] + 1];
			b[0] = img_48_data[i[0] + 2];
			a[0] = img_48_data[i[0] + 3];

			i[1] = (y * 48 + (x + 1)) * 4;
			r[1] = img_48_data[i[1] + 0];
			g[1] = img_48_data[i[1] + 1];
			b[1] = img_48_data[i[1] + 2];
			a[1] = img_48_data[i[1] + 3];

			i[2] = ((y + 1) * 48 + x) * 4;
			r[2] = img_48_data[i[2] + 0];
			g[2] = img_48_data[i[2] + 1];
			b[2] = img_48_data[i[2] + 2];
			a[2] = img_48_data[i[2] + 3];

			i[3] = ((y + 1) * 48 + (x + 1)) * 4;
			r[3] = img_48_data[i[3] + 0];
			g[3] = img_48_data[i[3] + 1];
			b[3] = img_48_data[i[3] + 2];
			a[3] = img_48_data[i[3] + 3];

			id = ((y / 2) * 24 + (x / 2)) * 4;
			img_24_data[id + 0] = (u8)((r[0] + r[1] + r[2] + r[3]) / 4);
			img_24_data[id + 1] = (u8)((g[0] + g[1] + g[2] + g[3]) / 4);
			img_24_data[id + 2] = (u8)((b[0] + b[1] + b[2] + b[3]) / 4);
			img_24_data[id + 3] = (u8)((a[0] + a[1] + a[2] + a[3]) / 4);
		}
	}
	GetTiledIconData(small_icon_, img_24_data, 24, 24);

	return 0;
}

void CtrAppIcon::ClearIconData()
{
	for (int i = 0; i < kSmallIconSize; i++)
	{
		small_icon_[i] = 0;
	}

	for (int i = 0; i < kLargeIconSize; i++)
	{
		large_icon_[i] = 0;
	}
}

u16 CtrAppIcon::PackColour(u8 r, u8 g, u8 b, u8 a)
{
	float alpha = a / 255.0f;
	r = (u8)(r * alpha) >> 3;
	g = (u8)(g * alpha) >> 2;
	b = (u8)(b * alpha) >> 3;
	return (r << 11) | (g << 5) | b;
}


void CtrAppIcon::GetTiledIconData(u16* out, u8* in, int height, int width)
{
	static const u8 TILE_ORDER[8*8] =
	{
		0,  1,  8,  9,  2,  3,  10, 11, 16, 17, 24, 25, 18, 19, 26, 27,
		4,  5,  12, 13, 6,  7,  14, 15, 20, 21, 28, 29, 22, 23, 30, 31,
		32, 33, 40, 41, 34, 35, 42, 43, 48, 49, 56, 57, 50, 51, 58, 59,
		36, 37, 44, 45, 38, 39, 46, 47, 52, 53, 60, 61, 54, 55, 62, 63
	};

	u32 n = 0;

	for (int y = 0; y < height; y += 8) {
		for (int x = 0; x < width; x += 8) {
			for (int k = 0; k < 8 * 8; k++) {
				u32 xx = (u32)(TILE_ORDER[k] & 0x7);
				u32 yy = (u32)(TILE_ORDER[k] >> 3);

				u8* pixel = in + (((y + yy) * width + (x + xx)) * 4);
				out[n++] = PackColour(pixel[0], pixel[1], pixel[2], pixel[3]);
			}
		}
	}
}