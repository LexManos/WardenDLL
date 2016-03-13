#ifndef RSA_C
#define RSA_C

#include "rsa.h"

uint32_t __stdcall rsa_buffer_size(){
	return sizeof(RSA);
}

uint32_t __stdcall rsa_hash_size(RSA *rsa){
	return RSA_size(rsa);
}
void __stdcall rsa_free(RSA *rsa){
	RSA_free(rsa);
}

uint32_t __stdcall rsa_create(RSA *rsa_out, uint32_t type, uint8_t *file_data){
	BIO *bio = NULL;
	RSA *rsa = NULL;

	if (type != RSA_CREATE_EMPTY){
		bio = BIO_new(BIO_s_mem());
  
		if (bio == NULL) {
			return RSA_BIO_FAILED;
		}
  
		BIO_puts(bio, file_data);
	
		if(type == RSA_PRIVATE)
			rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
		else if (type == RSA_PUBLIC)
			rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
		else if (type == 3)
			rsa = (RSA *)PEM_ASN1_read_bio((d2i_of_void (__cdecl *))d2i_RSA_PUBKEY, PEM_STRING_RSA_PUBLIC, bio, NULL, NULL, NULL);
		else{
			BIO_free(bio);
			return RSA_UNKNOWN_TYPE;
		}

		if (rsa == NULL){
			BIO_free(bio);
			return RSA_KEY_FAILED;
		}

		memcpy(rsa_out, rsa, sizeof(RSA));
		BIO_free(bio);
	}

	return RSA_SUCCESS;
}

uint32_t __stdcall rsa_crypt(RSA *rsa, uint32_t type, uint32_t encrypt, uint32_t padding, uint8_t *data, uint32_t data_length, uint8_t *buffer){
	if (type == RSA_PRIVATE){
		if(encrypt == RSA_ENCRYPT){
			if (RSA_private_encrypt((int)data_length, data, buffer, rsa, padding) != -1)
				return RSA_SUCCESS;
		}else{
			if (RSA_private_decrypt((int)data_length, data, buffer, rsa, padding) != -1)
				return RSA_SUCCESS;
		}
	}else if (type == RSA_PUBLIC){
		if(encrypt == RSA_ENCRYPT){
			if (RSA_public_encrypt((int)data_length, data, buffer, rsa, padding) != -1)
				return RSA_SUCCESS;
		}else{
			if (RSA_public_decrypt((int)data_length, data, buffer, rsa, padding) != -1)
				return RSA_SUCCESS;
		}
	}else{
		return RSA_UNKNOWN_TYPE;
	}
	//return RSA_CRYPT_FAILED;
	return ERR_get_error();
}

#endif
