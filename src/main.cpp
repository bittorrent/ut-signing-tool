/*
Copyright (c) 2012, BitTorrent Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "Bencode.h"

// OpenSSL became deprecated in Lion in favor of Apple's Common Crypto library
// we define this to avoid the compile time warnings
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_5

#include <openssl/err.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <pwd.h>

bool loadBencodedStdin(BencodeObject* obj) {
	const size_t block_size = 4096;
	char* buf = NULL;
	size_t len = 0;

	for (size_t i = 0; ; ++i) {
		buf = (char*)realloc(buf, (i + 1) * block_size);
		size_t bytes = fread(buf + i * block_size, 1, block_size, stdin);
		len += bytes;
		if (bytes < block_size) {
			break;
		}
	}
	
	BencodeObject tmp(buf, len, BencodeModeAdopt);

	if (tmp.type() == BencodeTypeInvalid) {
		fprintf(stderr, "Couldn't parse stdin.\n");
		return false;
	}
	
	*obj = tmp;
	
	return true;
}

bool loadBencodedFile(const char* filename, BencodeObject* obj) {
	FILE* f = fopen(filename, "rb");
	
	if (!f) {
		fprintf(stderr, "Couldn't open %s\n", filename);
		return false;
	}

	fseek(f, 0, SEEK_END);
	size_t f_size = ftell(f);
	fseek(f, 0, SEEK_SET);
	
	char* f_buff = (char*)malloc(f_size);
	
	if (!f_buff) {
		fprintf(stderr, "Out of memory!\n");
		fclose(f);
		return false;
	}
	
	if (fread(f_buff, f_size, 1, f) != 1) {
		fprintf(stderr, "Couldn't read %s\n", filename);
		free(f_buff);
		fclose(f);
		return false;
	}
	
	fclose(f);
	
	BencodeObject tmp(f_buff, f_size, BencodeModeAdopt);
	
	if (tmp.type() == BencodeTypeInvalid) {
		fprintf(stderr, "Couldn't parse %s\n", filename);
		return false;
	}
	
	*obj = tmp;

	return true;
}

int passwordCallback(char *buf, int size, int rwflag, void *u) {
	if (!u) {
		fprintf(stderr, "No password provided.\n");
		return 0;
	}

	size_t len = strlen((char*)u);

	if (len > size) {
		return 0;
	}

	memcpy(buf, u, len);

	return len;
}

#define CLEAN_UP() \
	if (f) { fclose(f); } \
	free(info_data); \
	free(sig_buff); \
	EVP_PKEY_free(private_key); \
	EVP_PKEY_free(public_key); \
	X509_free(x509); \
	if (md_ctx) { EVP_MD_CTX_destroy(md_ctx); }

#define ERROR_OUT(...) \
	fprintf(stderr, __VA_ARGS__); \
	CLEAN_UP(); \
	return 1;

#define OPENSSL_ERROR_OUT() \
	ERR_print_errors_fp(stderr); \
	CLEAN_UP(); \
	return 1;
	
#define LOGF(...) if (!useStdout) printf(__VA_ARGS__)

int main(int argc, const char* argv[]) {
	// these are things that have to be freed / closed
	FILE* f                 = NULL;
	EVP_PKEY* private_key   = NULL;
	EVP_PKEY* public_key    = NULL;
	X509* x509              = NULL;
	char* info_data         = NULL;
	unsigned char* sig_buff = NULL;
	EVP_MD_CTX* md_ctx      = NULL;
	
	// parse the arguments
	
	const char* filenames[4];
	bool includeCert = true;
	const char* password = NULL;
	const char* setUser = NULL;
	bool useStdin = false;
	bool useStdout = false;
	
	int fcount = 0;

	for (int i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--exclude-cert")) {
			includeCert = false;
		} else if (!strcmp(argv[i], "--password") && i + 1 < argc) {
			password = argv[++i];
		} else if (!strcmp(argv[i], "--setuser") && i + 1 < argc) {
			setUser = argv[++i];
		} else if (fcount < 4) {
			filenames[fcount++] = argv[i];
		}
	}
	
	if (fcount != 2 && fcount != 4) {
		ERROR_OUT("Usage: ut-signing-tool [--exclude-cert] [--password password] [--setuser user] privkey.pem cert.pem [in.torrent out.torrent]\n");
	}
	
	useStdin = useStdout = (fcount == 2);

	// read the private key

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	
	f = fopen(filenames[0], "r");
	if (!f) {
		ERROR_OUT("Couldn't open %s\n", filenames[0]);
	}

	private_key = PEM_read_PrivateKey(f, NULL, (useStdin || useStdout ? passwordCallback : NULL), (void*)password);
	
	if (!private_key) {
		OPENSSL_ERROR_OUT();
	}

	fclose(f);
	f = NULL;
	
	LOGF("Private key loaded.\n");
	
	// set uid to be safe
	
	struct passwd* pw = getpwnam(setUser);
	
	if (!pw) {
		ERROR_OUT("User %s doesn't exist.\n", setUser);
	}
	
	setuid(pw->pw_uid);

	// read the torrent

	BencodeObject torrent;

	if ((!useStdin && !loadBencodedFile(filenames[2], &torrent)) || (useStdin && !loadBencodedStdin(&torrent))) {
		ERROR_OUT("Couldn't load torrent.\n");
	}
	
	LOGF("Torrent loaded.\n");
	
	// read the certificate
	
	f = fopen(filenames[1], "r");
	if (!f) {
		ERROR_OUT("Couldn't open %s\n", filenames[1]);
	}

	x509 = PEM_read_X509(f, NULL, (useStdin || useStdout ? passwordCallback : NULL), (void*)password);
	
	if (!x509) {
		OPENSSL_ERROR_OUT();
	}

	fclose(f);
	f = NULL;

	char common_name[65];
	X509_NAME* name = X509_get_subject_name(x509);
	if (X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0) > 65) {
		ERROR_OUT("Invalid common name.\n");
	}
	X509_NAME_get_text_by_NID(name, NID_commonName, common_name, 65);

	LOGF("Certificate loaded. (identity = %s)\n", common_name);

	// create the signature

	BencodeObject* torrent_info = torrent.valueForKey("info");
	
	if (!torrent_info) {
		ERROR_OUT("Torrent info key not found.\n");
	}
	
	size_t info_size = torrent_info->serializedSize();
	if (!(info_data = (char*)malloc(info_size))) {
		ERROR_OUT("Out of memory!\n");
	}

	torrent_info->serialize(info_data, info_size);

	if (!(sig_buff = (unsigned char*)malloc(EVP_PKEY_size(private_key)))) {
		ERROR_OUT("Out of memory!\n");
	}	

	md_ctx = EVP_MD_CTX_create();
	EVP_SignInit(md_ctx, EVP_sha1());
	EVP_SignUpdate(md_ctx, info_data, info_size);

	unsigned int sig_len;
	if (!EVP_SignFinal(md_ctx, sig_buff, &sig_len, private_key)) {
		OPENSSL_ERROR_OUT();
	}
	
	LOGF("Signature size: %u\n", sig_len);
	
	// prepare the new file data
	
	BencodeObject signature(BencodeTypeDictionary);
	
	if (includeCert) {
		int clen = i2d_X509(x509, NULL);
		unsigned char* cbuff = (unsigned char*)malloc(clen);
		if (!cbuff) {
			ERROR_OUT("Out of memory!\n");
		}
		
		unsigned char* p = cbuff;
		clen = i2d_X509(x509, &p);

		if (clen < 0) {
			free(cbuff);
			OPENSSL_ERROR_OUT();
		}

		BencodeObject sig_certificate(BencodeTypeByteString);
		sig_certificate.setByteStringValue(cbuff, clen, BencodeModeAdopt);

		LOGF("Bencoded certificate size: %lu\n", sig_certificate.serializedSize());

		signature.setValueForKey("certificate", &sig_certificate);		
	}

	BencodeObject sig_signature(BencodeTypeByteString);
	sig_signature.setByteStringValue(sig_buff, sig_len);

	LOGF("Bencoded signature size: %lu\n", sig_signature.serializedSize());

	signature.setValueForKey("signature", &sig_signature);
	
	BencodeObject* signatures = torrent.valueForKey("signatures");
	
	if (!signatures || signatures->type() != BencodeTypeDictionary) {
		BencodeObject sigs(BencodeTypeDictionary);
		signatures = torrent.setValueForKey("signatures", &sigs);
	}

	signatures->setValueForKey(common_name, &signature);
	
	// write the file
	
	f = useStdout ? stdout : fopen(filenames[3], "wb");
	if (!f) {
		ERROR_OUT("Couldn't open %s\n", filenames[3]);
	}
	
	size_t outsize = torrent.serializedSize();
	char* outbuff = (char*)malloc(outsize);
	if (!outbuff) {
		ERROR_OUT("Out of memory!\n");
	}
	
	torrent.serialize(outbuff, outsize);
	
	if (fwrite(outbuff, outsize, 1, f) != 1) {
		free(outbuff);
		ERROR_OUT("Couldn't write torrent.\n");
	}
	
	free(outbuff);
	
	fclose(f);
	f = NULL;
	
	// done!
	
	LOGF("Done!\n");
	
	CLEAN_UP();
	
	return 0;
}
