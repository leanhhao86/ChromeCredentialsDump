#pragma warning(disable:4996)
#include "everything.h"
#include <openssl/applink.c>


void aes_gcm_decrypt(aes256gcm_info* info)

{
	outputaesinfo(info);
	EVP_CIPHER_CTX* ctx;

	int outlen, tmplen, rv;

	unsigned char outbuf[4096];

	printf("AES GCM Decrypt:\n");

	printf("Ciphertext:\n");

	BIO_dump_fp(stdout, (const char*)info->gcm_ct, info->gcm_ct_len);

	ctx = EVP_CIPHER_CTX_new();

	/* Select cipher */

	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

	/* Set IV length, omit for 96 bits */

	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, info->gcm_iv_len, NULL);
	EVP_CIPHER_CTX_set_key_length(ctx, info->gcm_key_len);
	/* Specify key and IV */

	EVP_DecryptInit_ex(ctx, NULL, NULL, info->gcm_key,  info->gcm_iv);

	/* Zero or more calls to specify any AAD */

	EVP_DecryptUpdate(ctx, NULL, &outlen,  info->gcm_aad, info->gcm_aad_len);

	/* Decrypt plaintext */

	EVP_DecryptUpdate(ctx, outbuf, &outlen,  info->gcm_ct, info->gcm_ct_len);

	/* Output decrypted block */

	printf("Plaintext:\n");

	BIO_dump_fp(stdout, (const char*) outbuf, outlen);

	/* Set expected tag value. */
	try {
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, info->gcm_tag_len, (void*)info->gcm_tag);
	}
	catch (int e) {
		std::cout << "Exception occurred " << e << std::endl;
		return;
	}


	/* Finalise: note get no output for GCM */

	rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);

	/*

	 * Print out return value. If this is not successful authentication

	 * failed and plaintext is not trustworthy.

	 */

	printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");

	EVP_CIPHER_CTX_free(ctx);

}
