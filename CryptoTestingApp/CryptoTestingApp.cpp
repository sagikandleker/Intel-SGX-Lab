// CryptoTestingApp.cpp : Defines the entry point for the console application.
//

#include <string.h>

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "stdio.h"
#include "stdlib.h"

#include <iostream>
#include <string>
using namespace std;

#define BUFLEN 2048
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12 //Initialization vector 96 bits, nonce

#define ENCLAVE_FILE "CryptoEnclave.signed.so"

int main()
{
	printf("Starting app...\n");
	
	/* Setup enclave */
	sgx_enclave_id_t eid;
	sgx_status_t ret;
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;
	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		getchar();
		return 1;
	}

	string receiveMessage;
	cout << "Please enter a message you want to encrypt \n";
  	getline (cin, receiveMessage);

	// It's easier to pass char* then string to enclave because of memory allocation.
	char message[receiveMessage.size() + 1];
	strcpy(message, receiveMessage.c_str());

	printf("Original message: %s\n", message);

	// The encrypted message will contain the MAC, the IV, and the encrypted message itself.
	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(message)); 
	char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));

	printf("Encrypting...\n");
	ret = encryptMessage(eid, message, strlen(message), encMessage, encMessageLen);
	encMessage[encMessageLen] = '\0';
	printf("Encrypted message: %s\n", encMessage);
	printf("encMessage size: %d\n", strlen(encMessage));
	
	
	// The decrypted message will contain the same message as the original one.
	char *decMessage = (char *) malloc((strlen(message)+1)*sizeof(char));

	printf("Decrypting...\n");
	ret = decryptMessage(eid,encMessage,encMessageLen,decMessage,strlen(message));
	decMessage[strlen(message)] = '\0';
	printf("Decrypted message: %s \n", decMessage);

	// getchar();
	return 0;
}