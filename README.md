# Intel® Software Guard Extensions (SGX)

By Shlomi Domnenko, Sagi Saada, and the other one

# Table of Contents

1. [Introduction](#introduction)
2. [Lab](#lab)
    1. [Lab Overview](#lab-overview)
    2. [Lab Environment](#lab-environment)
    3. [Lab Tasks](#lab-tasks)
3. [Difficulties](#difficulties)

# Introduction


Intel Software Security Extensions (SGX) is a set of security-related instruction codes that are built into some modern Intel central processing units (CPUs). They allow user-level as well as operating system code to define private regions of memory, called enclaves, whose contents are protected and unable to be either read or saved by any process outside the enclave itself, including processes running at higher privilege levels. SGX is disabled by default and must be opted in to by the user through their BIOS settings on a supported system.

SGX involves encryption by the CPU of a portion of memory. The enclave is decrypted on the fly only within the CPU itself, and even then, only for code and data running from within the enclave itself.
The processor thus protects the code from being "spied on" or examined by other code. The code and data in the enclave utilise a threat model in which the enclave is trusted but no process outside it (including the operating system itself and any hypervisor), can be trusted and these are all treated as potentially hostile. The enclave contents are unable to be read by any code outside the enclave, other than in its encrypted form.

# Lab

## Lab Overview

We will run simple Intel-SGX script. The script will ask for input, encrypt the message, and then decrypt it using AES_GCM algorithm.

## Lab Environment

In this lab we will use [Intel(R) Software Guard Extensions for Linux](https://github.com/intel/linux-sgx).

## Lab Tasks

Multiple files serve as enclave, trust and untrusted zones, and the application.

### Task 1: CryptoTestingApp.cpp
Our main app that create the enclave, uses it's hidded functions and destroy it in the end.

```c
#include "sgx_urts.h"
#include "CryptoEnclave_u.h"
#include "iostream"
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
	
	// The decrypted message will contain the same message as the original one.
	char *decMessage = (char *) malloc((strlen(message)+1)*sizeof(char));

	printf("Decrypting...\n");
	ret = decryptMessage(eid,encMessage,encMessageLen,decMessage,strlen(message));
	decMessage[strlen(message)] = '\0';
	printf("Decrypted message: %s \n", decMessage);

	sgx_destroy_enclave(eid);

	return 0;
}    
```

As it is in the untrusted application, we must include “sgx_urts.h”, the SGX untrusted runtime system, for SGX to work correctly with the application. We also include “CryptoEnclave_u.h”, which will include all of the ECALL proxies generated from the EDL file after compilation.

We didn't included all the possible error code caused by enclave operation because it's a proof of concept, but usually need to do that.

The critical function here is at line 24. It calls sgx_create_enclave() function provided by urts library to officially initialize the enclave instance. The sgx_create_enclave() will performs an implicit ECALL. The implicit ECALL initiates enclave runtime initialization flow described in the Enclave Lifecycle tutorial provided by intel. The actual enclave instance shared object will be saved as “CryptoEnclave.signed.so”, which is signed by the CPU as indicated by the filename. And the enclave id will be saved in “global_eid” for future access.

In the main body of the application, we first initialize the enclave by calling sgx_create_enclave(). Then call our encryptMessage() and decryptMessage() functions, which will be discussed later.

Finally, we destroy the enclave instance by calling sgx_destroy_enclave() provided by urts library. It will perform the implicit ECALL that performs instructions that destry the targeted enclave.

### Task 2: CryptoEnclave.cpp
Our enclave has two functions that are hidded from the outside world, decryptMessage and encryptMessage.
those two functuons uses sgx ssl libraries to encrypt and decrypt our message.

```c
#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "string.h"
#include "stdio.h"

#define BUFLEN 2048
static sgx_aes_gcm_128bit_key_t key = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xc };

void decryptMessage(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut)
{
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	sgx_rijndael128GCM_decrypt(
		&key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage);
	memcpy(decMessageOut, p_dst, lenOut);
}

void encryptMessage(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut)
{
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};
	int buf_size = 100;

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

	sgx_rijndael128GCM_encrypt(
		&key,
		origMessage, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst));	
	memcpy(encMessageOut,p_dst,lenOut);
}
```

### Task 3: CryptoEnclave.edl
We can verify that after compiling the whole project.
Therefore, in order to let the Edger8r generate the corresponding proxy functions, we put our functions decryptMessage() and encryptMessage in the trusted section of “CryptoEnclave.edl”. 
```c
enclave {
    trusted {
        /*
        * This function decrypts a message.
        * @param encMessageIn
        *    the encrypted message containing MAC + IV + encrypted message.
        * @param len
        *    the length of the encMessageIn.
        * @param decMessageOut
        *    the destination of the decrypted message.
        * @param lenOut
        *    the length of the decMessageOut.
        */
        public void decryptMessage([in,size=len] char *encMessageIn, size_t len, [out,size=lenOut] char *decMessageOut, size_t lenOut);
        
        /*
        * This function encrypts a message.
        * @param decMessageIn
        *    the original message
        * @param len
        *    the length of the decMessageIn.
        * @param encMessageOut
        *    the destination of the encrypted message containing MAC + IV + encrypted message.
        * @param lenOut
        *    the length of the encMessageOut.
        */
        public void encryptMessage([in,size=len] char *decMessageIn, size_t len, [out,size=lenOut] char *encMessageOut, size_t lenOut);
    };

    untrusted {
    };
};
```

# Difficulties

When we first met SGX it was horrible to work with. We had a lot of trouble getting everything working. Especially SGX PSW, SGX drivers, SGX SDK. Everytime we had problem ontop of another. We eventually succeeded in running the lab, by doing research on Google and visiting a lot of places.
