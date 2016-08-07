#include <stdlib.h>
#include <vector>
#include "oschar.h"

int os_fstat(const oschar_t *path)
{
	struct _osstat st;
	return os_stat(path, &st);
}

uint64_t os_fsize(const oschar_t *path)
{
	struct _osstat st;
	if (os_stat(path, &st) != 0)
		return 0;
	else
		return st.st_size;
}

int os_makedir(const oschar_t *dir)
{
#ifdef _WIN32
	return _wmkdir(dir);
#else
	return mkdir(dir, 0777);
#endif
}

uint32_t utf16_strlen(const utf16char_t *str)
{
	uint32_t i;
	for (i = 0; str[i] != 0x0; i++);
	return i;
}

char* strcopy_8to8(const char *src)
{
	uint32_t src_len;
	char *dst;

	if (!src)
		return NULL;

	src_len = strlen(src);

	// Allocate memory for expanded string
	dst = (char*)calloc(src_len + 1, sizeof(char));
	if (!dst)
		return NULL;

	// Copy elements from src into dst
	strncpy(dst, src, src_len);

	return dst;
}

utf16char_t* strcopy_8to16(const char *src)
{
	uint32_t src_len, i;
	utf16char_t *dst;

	if (!src)
		return NULL;

	src_len = strlen(src);

	// Allocate memory for expanded string
	dst = (utf16char_t*)calloc(src_len + 1, sizeof(utf16char_t));
	if (!dst)
		return NULL;

	// Copy elements from src into dst
	for (i = 0; i < src_len; i++)
		dst[i] = src[i];

	return dst;
}


utf16char_t* strcopy_16to16(const utf16char_t *src)
{
	uint32_t src_len, i;
	utf16char_t *dst;

	if (!src)
		return NULL;

	src_len = utf16_strlen(src);

	// Allocate memory for expanded string
	dst = (utf16char_t*)calloc(src_len + 1, sizeof(utf16char_t));
	if (!dst)
		return NULL;

	// Copy elements from src into dst
	for (i = 0; i < src_len; i++)
		dst[i] = src[i];

	return dst;
}

#ifndef _WIN32
// Function written by mtheall
static ssize_t decode_utf8(uint32_t *out, const uint8_t *in)
{
	uint8_t code1, code2, code3, code4;

	code1 = *in++;
	if (code1 < 0x80)
	{
		// 1-byte sequence
		*out = code1;
		return 1;
	}
	else if (code1 < 0xC2)
		return -1;
	else if (code1 < 0xE0)
	{
		// 2-byte sequence
		code2 = *in++;
		if ((code2 & 0xC0) != 0x80)
			return -1;

		*out = (code1 << 6) + code2 - 0x3080;
		return 2;
	}
	else if (code1 < 0xF0)
	{
		/* 3-byte sequence */
		code2 = *in++;
		if ((code2 & 0xC0) != 0x80)
			return -1;
		if (code1 == 0xE0 && code2 < 0xA0)
			return -1;

		code3 = *in++;
		if ((code3 & 0xC0) != 0x80)
			return -1;

		*out = (code1 << 12) + (code2 << 6) + code3 - 0xE2080;
		return 3;
	}
	else if (code1 < 0xF5)
	{
		// 4-byte sequence
		code2 = *in++;
		if ((code2 & 0xC0) != 0x80)
			return -1;
		if (code1 == 0xF0 && code2 < 0x90)
			return -1;
		if (code1 == 0xF4 && code2 >= 0x90)
			return -1;

		code3 = *in++;
		if ((code3 & 0xC0) != 0x80)
			return -1;

		code4 = *in++;
		if ((code4 & 0xC0) != 0x80)
			return -1;

		*out = (code1 << 18) + (code2 << 12) + (code3 << 6) + code4 - 0x3C82080;
		return 4;
	}

	return -1;
}

utf16char_t* strcopy_UTF8toUTF16(const char *src)
{
    // convert src
	std::vector<utf16char_t> rstr;
	rstr.clear();
	rstr.clear();
	for (;;)
	{
		uint32_t code = 0;
		ssize_t units = decode_utf8(&code, (const uint8_t*)src);
		if (units == -1)
		{
			rstr.push_back(0xFFFD); // Replacement character
			src++;
			continue;
		}
		if (code == 0)
			break;

		// Encode Unicode codepoint as UTF-16
		if (code < 0x10000)
			rstr.push_back(code);
		else if (code < 0x110000)
		{
			rstr.push_back((code >> 10) + 0xD7C0);
			rstr.push_back((code & 0x3FF) + 0xDC00);
		}
		else
			rstr.push_back(0xFFFD); // Replacement character

		src += units;
	}
    
    // save converted src
	utf16char_t *out = (utf16char_t*)calloc(sizeof(utf16char_t), rstr.size()+1);
	size_t i;
	for (i = 0; i < rstr.size(); i++)
	{
		out[i] = rstr[i];
	}
	out[i] = '\0';

	return out;
}
#endif

oschar_t* os_AppendToPath(const oschar_t *src, const oschar_t *add)
{
	uint32_t len;
	oschar_t *new_path;

	len = os_strlen(src) + os_strlen(add) + 0x10;
	new_path = (oschar_t*)calloc(len, sizeof(oschar_t));

#ifdef _WIN32
	_snwprintf(new_path, len, L"%s%c%s", src, OS_PATH_SEPARATOR, add);
#else
	snprintf(new_path, len, "%s%c%s", src, OS_PATH_SEPARATOR, add);
#endif

	return new_path;
}
