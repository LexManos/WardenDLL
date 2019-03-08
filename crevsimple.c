#include "crevsimple.h"

/**
 * CheckRevison.dll:
 *   Used on Diablo 2. 
 *   ret = base64_encode(sha1(base64_decode(seed), ':', ExeVersionString, ':', (byte)1))
 *   version = 0
 *   checksum = first 4 bytes of ret
 *   result = the rest of ret
 *
 *
 * CheckRevisionD1.dll
 *   Used by Diablo 1 on GoG version/custom server.
 *   ret = base64_encode(sha1(base64_decode(seed), ':', ExeVersionString, ':', (byte)1)) + ':' + base64_encode(sha1(ExeCert, base64_decode(seed)))
 *   version = 6
 *   checksum = first 4 bytes of ret
 *   result = the rest of ret
 */

uint32_t __stdcall crev_simple(uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, uint8_t *ini_file, uint8_t *ini_header, uint32_t *version, uint32_t *checksum, uint8_t *result) {
	*version = 0;
	return crev_simple_impl(archive_time, archive_name, seed, ini_file, ini_header, version, checksum, result, FALSE);
}

uint32_t __stdcall crev_simple_d1(uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, uint8_t *ini_file, uint8_t *ini_header, uint32_t *version, uint32_t *checksum, uint8_t *result) {
	*version = 6;
	return crev_simple_impl(archive_time, archive_name, seed, ini_file, ini_header, version, checksum, result, TRUE);
}

uint32_t __stdcall crev_simple_impl(uint8_t *archive_time, uint8_t *archive_name, uint8_t *seed, uint8_t *ini_file, uint8_t *ini_header, uint32_t *version, uint32_t *checksum, uint8_t *result, BOOLEAN include_cert) {
	//uint8_t *debug = safe_malloc(MAX_PATH*2);
	uint8_t *root = safe_malloc(MAX_PATH);
	uint8_t *exe = safe_malloc(MAX_PATH);
	uint8_t *buff = safe_malloc(MAX_PATH);
	uint8_t *sha_hash = safe_malloc(sha1_hash_size);
	uint8_t *version_info = NULL;
	uint32_t ret = CREV_UNKNOWN_VERSION;
	uint32_t size;
	uint32_t x;
	uint32_t offset;
	uint8_t *seed_decoded = NULL;
	uint8_t *version_str;
	uint8_t *exe_cert = NULL;
	uint32_t cert_len;
	uint8_t *cert_hash = safe_malloc(sha1_hash_size);
	sha1_context sha;

	//sprintf_s(debug, MAX_PATH*2, "INI Path: %s\n", ini_file); write_to_file(debug);
	read_ini_new(ini_file, ini_header, "Path", "", buff, MAX_PATH);
	combine_paths(buff, "", root, MAX_PATH);

	read_ini_new(ini_file, ini_header, "Exe", "\xFF", buff, MAX_PATH);
	if (buff[0] == 0xFF || _stricmp(buff, "NULL") == 0){
		sprintf_s(result, crev_max_result(), "Exe\x00");
		ret = CREV_MISSING_FILENAME;
	} else {
		combine_paths(root, buff, exe, MAX_PATH);
		//sprintf_s(debug, MAX_PATH*2, "Exe Path: %s\n", exe); write_to_file(debug);
		//sprintf_s(debug, MAX_PATH*2, "Seed: %s\n", seed); write_to_file(debug);

		size = base64_decode_size(strlen(seed));
		seed_decoded = safe_malloc(size);
		size = base64_decode(seed, strlen(seed), seed_decoded, size);
		//sprintf_s(debug, MAX_PATH*2, "Seed Decoded: %s\n", to_hex(seed_decoded, size, TRUE)); write_to_file(debug);
		
		size = GetFileVersionInfoSize(exe, NULL);
		if (size == 0) {
			sprintf_s(result, crev_max_result(), "Could not get GetFileVersionInfoSize for %s\x00", exe);
			ret = CREV_MISSING_FILENAME;
		} else {
			version_info = safe_malloc(size);
			if (GetFileVersionInfo(exe, (DWORD)NULL, size, (uint8_t*)version_info) == 0){
				sprintf_s(result, crev_max_result(), "Could not get GetFileVersionInfo for %s\x00", exe);
				ret = CREV_MISSING_FILENAME;
			} else {
				if (VerQueryValue(version_info, "\\StringFileInfo\\040904b0\\FileVersion", &version_str, &size) == 0 &&
					VerQueryValue(version_info, "\\StringFileInfo\\000004b0\\FileVersion", &version_str, &size) == 0){
						sprintf_s(result, crev_max_result(), "Could not find FileVersion entry for %s\x00", exe);
						ret = CREV_MISSING_FILENAME;
				} else {
					//sprintf_s(debug, MAX_PATH*2, "File Version: %s\n", version_str); write_to_file(debug);
					sha.version = SHA1;
					sha1_reset(&sha);
					sha1_input(&sha, seed_decoded, 4);
					sha1_input(&sha, ":", 1);
					sha1_input(&sha, version_str, strlen(version_str));
					sha1_input(&sha, ":", 1);
					sha1_input(&sha, "\x01", 1);
					sha1_digest(&sha, sha_hash);
					//sprintf_s(debug, MAX_PATH*2, "Hash: %s\n", to_hex(sha_hash, sha1_hash_size, TRUE)); write_to_file(debug);
					free(buff);
					size = base64_encode_size(sha1_hash_size);
					buff = safe_malloc(size+1);
					memset(buff, 0, size+1);
					size = base64_encode(sha_hash, sha1_hash_size, buff, size);
					//sprintf_s(debug, MAX_PATH*2, "Encoded: %s\n", buff); write_to_file(debug);

					*checksum = buff[0] | (buff[1] << 8) | (buff[2] << 16) | (buff[3] << 24);
					for (x = 4; x < size; x++) {
						result[x-4] = buff[x];
					}
					result[size-4] = 0;

					if (include_cert) {
						cert_len = crev_get_file_public_key(exe, &exe_cert);
						//sprintf_s(debug, MAX_PATH*2, "Cert Len: %d\n", cert_len); write_to_file(debug);
						if (cert_len == 0) {
							sprintf_s(result, crev_max_result(), "Could not get EXE file's certificate bytes");
							ret = CREV_FILE_INFO_ERROR;
						} else {
							sha1_reset(&sha);
							sha1_input(&sha, exe_cert, cert_len);
							sha1_input(&sha, seed_decoded, 4);
							sha1_digest(&sha, cert_hash);
							//sprintf_s(debug, MAX_PATH*2, "Cert Hash: %s\n", to_hex(cert_hash, sha1_hash_size, TRUE)); write_to_file(debug);

							offset = size - 4;
							size = base64_encode_size(sha1_hash_size);
							memset(buff, 0, size+1);
							size = base64_encode(cert_hash, sha1_hash_size, buff, size);

							result[offset] = ':';
							for(x = 0; x < size; x++) {
								result[offset + 1 + x] = buff[x];
							}
							ret = CREV_SUCCESS;
						}
					} else {
						ret = CREV_SUCCESS;
					}
				}
			}
		}
	}

	//free(debug);
	free(root);
	free(exe);
	free(buff);
	free(sha_hash);
	free(cert_hash);
	if (seed_decoded != NULL)
		free(seed_decoded);
	if (version_info != NULL)
		free(version_info);
	if (exe_cert != NULL)
		free(exe_cert);

	return ret;
}

uint32_t __stdcall crev_get_file_public_key(uint8_t *file, uint8_t **key) {
	//uint8_t *debug = safe_malloc(MAX_PATH*2);
	uint32_t pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType;
	HCERTSTORE phCertStore;
	HCRYPTMSG phMsg;
	uint32_t key_size = 0;
	WCHAR wcFile[MAX_PATH];
	uint8_t *signerInfo = NULL;
	uint32_t signerInfoSize;
	uint32_t result;
	CERT_INFO certInfo;
	CERT_CONTEXT *certContext;
	CRYPT_BIT_BLOB publicKey;

	mbstowcs_s(&result, wcFile, MAX_PATH, file, strlen(file));

	if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wcFile, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_BASE64_ENCODED, 0, &pdwMsgAndCertEncodingType, &pdwContentType, &pdwFormatType, &phCertStore, &phMsg, NULL) &&
		CryptMsgGetParam(phMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize)) {
		signerInfo = safe_malloc(signerInfoSize);
		//sprintf_s(debug, MAX_PATH*2, "Cert signer size %08x\n", signerInfoSize); write_to_file(debug);
		if (CryptMsgGetParam(phMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo, &signerInfoSize)) {
			certInfo.Issuer = ((CMSG_SIGNER_INFO*)signerInfo)->Issuer;
			certInfo.SerialNumber = ((CMSG_SIGNER_INFO*)signerInfo)->SerialNumber;
			certContext = CertFindCertificateInStore(phCertStore, PKCS_7_ASN_ENCODING | CRYPT_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
			if (certContext != NULL) {
				publicKey = certContext->pCertInfo->SubjectPublicKeyInfo.PublicKey;
				//sprintf_s(debug, MAX_PATH*2, "Public Key Size %08x Unused Bits: %d\n", publicKey.cbData, publicKey.cUnusedBits); write_to_file(debug);
				key_size = publicKey.cbData;
				*key = safe_malloc(key_size);
				memcpy(*key, publicKey.pbData, key_size);
				//write_to_file(to_hex(*key, key_size, TRUE));
				CertFreeCertificateContext(certContext);
			}
		}
	} else {
		result = GetLastError();
		//sprintf_s(debug, MAX_PATH*2, "Cert Error %08x: %s\n", result, strerror(result)); write_to_file(debug);
	}

	//free(debug);
	if (signerInfo != NULL)
		free(signerInfo);
	return key_size;
}
