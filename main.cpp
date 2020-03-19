/* Decrypt Chrome 80's credentials */
/*
+-------------------------+
| Decrypted Master Key    |
| from 'Local State' file +------------v
|                         |        +--------------------+     +-------------------+
+-------------------------+        | AES-256 GCM mode   |     |Decrypted password |
								   |    cipher          +---->+                   |
+-------------------------+        +----^---------------+     +-------------------+
| Sqlite3 password blob   |             |
| (ciphertext, iv, tag)   +-------------+
|                         |
+-------------------------+

*/


#include "everything.h"

using namespace std;

int main() {
	char errMsg[MAX_PATH];
	int version = 80;
	LPSTR versionPath;
	LPSTR localStatePath;
	LPSTR loginDataPath;
	LPSTR cookiePath;
	DATA_BLOB dataIn = { 0 };
	DATA_BLOB dataOut = { 0 };
	BYTE* decrypted_key = (BYTE*) malloc(EVP_MAX_KEY_LENGTH);

	/* Get database and json file path */
	getVersionPath(&versionPath);
	getLocalStatePath(&localStatePath);
	getLoginDataPath(&loginDataPath);
	getCookiePath(&cookiePath);

	/* Check verion */
	ifstream versionfile(versionPath);
	string versionStr; versionfile >> versionStr;
	int pos = versionStr.find('.', 0);
	if (pos > -1) {
		if (stoi(versionStr.substr(0, pos + 1)) >= 80) 	
			cout << "Chrome version: " << version << endl;
	}

	/* Decrypt master key*/
	Json::Value root;
	ifstream localStateFile(localStatePath);
	if (!localStateFile.is_open()) {
		_strerror_s(errMsg, "failed to open file");
	}
	// parse JSON file and decode
	localStateFile >> root;
	string encrypted_key = root["os_crypt"].get("encrypted_key", "UTF-8").asString();
	string decoded = base64_decode(encrypted_key);
	// cout << decoded << endl;
	decoded = decoded.substr(5);
	// DPAPI decrypt
	dataIn.cbData = decoded.size();
	dataIn.pbData = (BYTE*)malloc(dataIn.cbData);
	memcpy(dataIn.pbData, decoded.c_str(), dataIn.cbData);

	if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut))
		ReportError("Failed to decypt master key", 1, true);
	// cout << dataOut.cbData << endl;
	// cout << dataOut.pbData << endl;
	memcpy(decrypted_key, dataOut.pbData, EVP_MAX_KEY_LENGTH);
	/* Decrypt login data */
	loginDataDecrypt(loginDataPath, decrypted_key);
	/* Decrypt cookie */
	cookieDecrypt(cookiePath, decrypted_key);
	free(decrypted_key);
	return 0;
}