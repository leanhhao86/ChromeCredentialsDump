#pragma once
#pragma comment(lib, "crypt32.lib")
#include <sys/stat.h>
#include <Windows.h>
#include <shlobj_core.h>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "base64.h"
#include "sqlite3.h"
#include "everything.h"
#include "json.h"
#include "json-forwards.h"

typedef struct aes256gcm_info {
	unsigned char* gcm_key;
	int gcm_key_len;
	unsigned char* gcm_iv;
	int gcm_iv_len;
	unsigned char* gcm_aad;
	int gcm_aad_len;
	unsigned char* gcm_ct;
	int gcm_ct_len;
	unsigned char* gcm_tag;
	int gcm_tag_len;
} aes256gcm_info;

VOID ReportError(LPCSTR userMessage, DWORD exitCode, BOOL printErrorMessage);
VOID ReportException(LPSTR userMessage, DWORD exceptionCode);
BOOL isFileGood(LPCSTR filename);
bool getLocalAppDataPath(LPSTR* path);
bool getVersionPath(LPSTR* path);
bool getLocalStatePath(LPSTR* path);
bool getLoginDataPath(LPSTR* path);
bool getCookiePath(LPSTR* path);
void loginDataDecrypt(LPSTR loginDataPath, BYTE* key);
void cookieDecrypt(LPSTR cookiePath, BYTE* key);
void fillAES256GCM(aes256gcm_info* info, BYTE* key, int key_len, BYTE* buffer, int len);
void freeAES256GCM(aes256gcm_info* info);
void aes_gcm_decrypt(aes256gcm_info*);
void outputaesinfo(aes256gcm_info* info);
