#pragma once
#ifdef _WIN32
#include <wchar.h>
#endif
#include <cstdio>
#include <cstring>
#include <inttypes.h>
#include <sys/stat.h>

#ifndef _MSC_VER
#include <dirent.h>
#else
#include <windows.h>
#endif


// Nintendo uses UTF16-LE chars for extended ASCII support


// Native OS char type for unicode support
#ifdef _WIN32
#define oschar_t wchar_t  // UTF16-LE
#define utf16char_t wchar_t
#else
#define oschar_t char  // UTF8
#define utf16char_t uint16_t
#endif

// Simple redirect macros for functions and types
#ifdef _WIN32
#define os_strlen wcslen
#define os_strcmp wcscmp
#define os_fputs fputws

#define os_CopyStr (oschar_t*)strcopy_16to16
#define os_CopyConvertCharStr (oschar_t*)strcopy_8to16
//#define os_CopyConvertUTF16Str (oschar_t*)strcopy_16to16
#define utf16_CopyStr (utf16char_t*)strcopy_16to16
#define utf16_CopyConvertOsStr (utf16char_t*)strcopy_16to16

#define _osdirent _wdirent
#define _OSDIR _WDIR
#define os_readdir _wreaddir
#define os_opendir _wopendir
#define os_closedir _wclosedir
#define os_chdir _wchdir

#define _osstat _stat64
#define os_stat _wstat64

#define os_fopen _wfopen
#define OS_MODE_READ L"rb"
#define OS_MODE_WRITE L"wb"
#define OS_MODE_EDIT L"rb+"
#define OS_PATH_SEPARATOR '\\'
#else
#define os_strlen strlen
#define os_strcmp strcmp
#define os_fputs fputs

#define os_CopyStr (oschar_t*)strcopy_8to8
#define os_CopyConvertCharStr (oschar_t*)strcopy_8to8
//#define os_CopyConvertUTF16Str (oschar_t*)strcopy_UTF16toUTF8
#define utf16_CopyStr (utf16char_t*)strcopy_16to16
#define utf16_CopyConvertOsStr (utf16char_t*)strcopy_UTF8toUTF16

#define _osdirent dirent
#define _OSDIR DIR
#define os_readdir readdir
#define os_opendir opendir
#define os_closedir closedir
#define os_chdir chdir

#define _osstat stat
#define os_stat stat

#define os_fopen fopen
#define OS_MODE_READ "rb"
#define OS_MODE_WRITE "wb"
#define OS_MODE_EDIT "rb+"
#define OS_PATH_SEPARATOR '/'
#endif

/* File related */
int os_fstat(const oschar_t* path);
uint64_t os_fsize(const oschar_t* path);
int os_makedir(const oschar_t* dir);

/* UTF16 String property functions */
uint32_t utf16_strlen(const utf16char_t* str);

/* String Copy and Conversion */
char* strcopy_8to8(const char* src);
utf16char_t* strcopy_8to16(const char* src);
utf16char_t* strcopy_16to16(const utf16char_t* src);
#ifndef _WIN32
utf16char_t* strcopy_UTF8toUTF16(const char* src);
char* strcopy_UTF16toUTF8(const utf16char_t* src);
#endif

/* String Append and Create */
oschar_t* os_AppendToPath(const oschar_t* src, const oschar_t* add);